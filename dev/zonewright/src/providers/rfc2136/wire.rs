//! The DNS message format, as far as this client needs it: building UPDATE and QUERY messages
//! without name compression and reading answers with it.
//!
//! Sources: RFC 1035 section 4.1 (header, question and resource record layout; name compression
//! in 4.1.4), RFC 2136 section 2 (the UPDATE message: opcode 5, the zone, prerequisite, update and
//! additional sections, the class values that select an operation), RFC 3597 section 4 (which
//! types may carry compressed names inside their RDATA).
//!
//! Every read checks its bounds; a message that does not parse is an error value, never a panic.

use std::ops::Range;

use crate::error::Error;
use crate::name::{DomainName, TargetName};
use crate::redact::Detail;

/// Type code of NS (RFC 1035 section 3.2.2).
pub(super) const TYPE_NS: u16 = 2;
/// Type code of CNAME (RFC 1035 section 3.2.2).
pub(super) const TYPE_CNAME: u16 = 5;
/// Type code of SOA (RFC 1035 section 3.2.2).
pub(super) const TYPE_SOA: u16 = 6;
/// Type code of TXT (RFC 1035 section 3.2.2).
pub(super) const TYPE_TXT: u16 = 16;
/// Type code of TSIG (RFC 8945 section 4.2).
pub(super) const TYPE_TSIG: u16 = 250;
/// Type code ANY (RFC 1035 section 3.2.3).
pub(super) const TYPE_ANY: u16 = 255;
/// Class IN (RFC 1035 section 3.2.4).
pub(super) const CLASS_IN: u16 = 1;
/// Class NONE: "delete an RR from an RRset" (RFC 2136 sections 1.3 and 2.5.4).
pub(super) const CLASS_NONE: u16 = 254;
/// Class ANY (RFC 1035 section 3.2.5; RFC 2136 section 2.4.4; RFC 8945 section 4.2).
pub(super) const CLASS_ANY: u16 = 255;
/// Opcode QUERY (RFC 1035 section 4.1.1).
pub(super) const OPCODE_QUERY: u8 = 0;
/// Opcode UPDATE (RFC 2136 section 2.2).
pub(super) const OPCODE_UPDATE: u8 = 5;

/// Length of the header (RFC 1035 section 4.1.1).
pub(super) const HEADER_LEN: usize = 12;
/// Offset of ARCOUNT in the header.
pub(super) const ARCOUNT_AT: usize = 10;
/// The largest message the TCP framing can carry: its length prefix is two octets (RFC 1035
/// section 4.2.2).
pub(super) const MAX_MESSAGE: usize = 65_535;
/// The longest name in wire form (RFC 1035 section 3.1).
const MAX_NAME: usize = 255;
/// Most compression pointers followed in one name; a chain this long is a loop.
const MAX_POINTERS: usize = 64;

/// Response codes (RFC 1035 section 4.1.1, RFC 2136 section 2.2).
pub(super) mod rcode {
    /// No error.
    pub(in super::super) const NOERROR: u8 = 0;
    /// The server could not interpret the request.
    pub(in super::super) const FORMERR: u8 = 1;
    /// Internal failure of the server.
    pub(in super::super) const SERVFAIL: u8 = 2;
    /// A name that ought to exist does not.
    pub(in super::super) const NXDOMAIN: u8 = 3;
    /// The opcode is not supported.
    pub(in super::super) const NOTIMP: u8 = 4;
    /// Refused for policy reasons.
    pub(in super::super) const REFUSED: u8 = 5;
    /// A name that ought not to exist does.
    pub(in super::super) const YXDOMAIN: u8 = 6;
    /// An RRset that ought not to exist does.
    pub(in super::super) const YXRRSET: u8 = 7;
    /// An RRset that ought to exist does not.
    pub(in super::super) const NXRRSET: u8 = 8;
    /// The server is not authoritative for the zone (also the RCODE of TSIG errors, RFC 8945
    /// section 5.2).
    pub(in super::super) const NOTAUTH: u8 = 9;
    /// A name is not within the zone of the zone section.
    pub(in super::super) const NOTZONE: u8 = 10;
}

fn invalid(text: &'static str) -> Error {
    Error::InvalidInput {
        code: None,
        detail: Detail::constant(text),
    }
}

/// Appends `name` uncompressed, lowercase (the canonical form of RFC 4034 section 6.2, which
/// RFC 8945 section 4.3.3 requires for the TSIG variables).
pub(super) fn put_name(out: &mut Vec<u8>, name: &DomainName) {
    out.extend_from_slice(TargetName::from(name).wire());
}

/// The big-endian 16-bit number at `at`, if the buffer holds it.
pub(super) fn be16(buf: &[u8], at: usize) -> Option<u16> {
    match buf.get(at..at.checked_add(2)?)? {
        [a, b] => Some(u16::from_be_bytes([*a, *b])),
        _ => None,
    }
}

/// Appends a 16-bit length; fails above 65535.
fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), Error> {
    let len = u16::try_from(len).map_err(|_| invalid("a DNS message field is too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

/// The question of a request, as the answer must repeat it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Question {
    /// Lowercase, with the trailing dot, in the spelling of [`Reader::name`].
    pub(super) name: String,
    /// The question type.
    pub(super) qtype: u16,
    /// The question class.
    pub(super) qclass: u16,
}

/// A message without TSIG, built section by section.
pub(super) struct Builder {
    opcode: u8,
    question: Question,
    question_wire: Vec<u8>,
    /// Prerequisite (answer), update (authority) and additional sections.
    sections: [Vec<u8>; 3],
    counts: [u16; 3],
}

impl Builder {
    fn new(opcode: u8, name: &DomainName, qtype: u16) -> Builder {
        let mut question_wire = Vec::with_capacity(MAX_NAME + 4);
        put_name(&mut question_wire, name);
        question_wire.extend_from_slice(&qtype.to_be_bytes());
        question_wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        Builder {
            opcode,
            question: Question {
                name: name.as_str().to_owned(),
                qtype,
                qclass: CLASS_IN,
            },
            question_wire,
            sections: Default::default(),
            counts: [0; 3],
        }
    }

    /// A query for `name` and `qtype`, class IN, recursion not desired (RFC 1035 section 4.1.1):
    /// the server answers from its own data.
    pub(super) fn query(name: &DomainName, qtype: u16) -> Builder {
        Builder::new(OPCODE_QUERY, name, qtype)
    }

    /// An UPDATE of `zone`: the zone section is `zone SOA IN` (RFC 2136 section 2.3).
    pub(super) fn update(zone: &DomainName) -> Builder {
        Builder::new(OPCODE_UPDATE, zone, TYPE_SOA)
    }

    fn rr(
        &mut self,
        section: usize,
        name: &DomainName,
        rtype: u16,
        class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Result<(), Error> {
        let (Some(out), Some(count)) =
            (self.sections.get_mut(section), self.counts.get_mut(section))
        else {
            return Err(invalid("a DNS message section is out of range"));
        };
        *count = count
            .checked_add(1)
            .ok_or_else(|| invalid("a DNS message section has too many records"))?;
        put_name(out, name);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        put_len(out, rdata.len())?;
        out.extend_from_slice(rdata);
        Ok(())
    }

    /// Prerequisite "name is in use" (RFC 2136 section 2.4.4): class ANY, type ANY, TTL 0, no
    /// RDATA.
    pub(super) fn prereq_name_in_use(&mut self, name: &DomainName) -> Result<(), Error> {
        self.rr(0, name, TYPE_ANY, CLASS_ANY, 0, &[])
    }

    /// Prerequisite "RRset does not exist" (RFC 2136 section 2.4.3): class NONE, the type, TTL
    /// 0, no RDATA. A server answers YXRRSET when the RRset exists (section 3.2.5).
    pub(super) fn prereq_rrset_absent(
        &mut self,
        name: &DomainName,
        rtype: u16,
    ) -> Result<(), Error> {
        self.rr(0, name, rtype, CLASS_NONE, 0, &[])
    }

    /// Prerequisite "name is not in use" (RFC 2136 section 2.4.5): class NONE, type ANY, TTL 0,
    /// no RDATA. A server answers YXDOMAIN when the name owns any RR (section 3.2.2).
    pub(super) fn prereq_name_unused(&mut self, name: &DomainName) -> Result<(), Error> {
        self.rr(0, name, TYPE_ANY, CLASS_NONE, 0, &[])
    }

    /// One RR of the prerequisite "RRset exists (value dependent)" (RFC 2136 section 2.4.2): the
    /// zone's class, TTL 0, the RDATA. The RRs given for one name and type form the RRset the
    /// zone must hold exactly; a server answers NXRRSET otherwise (section 3.2.3).
    pub(super) fn prereq_rr(
        &mut self,
        name: &DomainName,
        rtype: u16,
        rdata: &[u8],
    ) -> Result<(), Error> {
        self.rr(0, name, rtype, CLASS_IN, 0, rdata)
    }

    /// "Delete an RRset" (RFC 2136 section 2.5.2): class ANY, the type, TTL 0, no RDATA. Type
    /// ANY would be "delete all RRsets from a name" (section 2.5.3), which this client never
    /// sends; it is refused here.
    pub(super) fn delete_rrset(&mut self, name: &DomainName, rtype: u16) -> Result<(), Error> {
        if rtype == TYPE_ANY {
            return Err(invalid("the client never deletes every RRset of a name"));
        }
        self.rr(1, name, rtype, CLASS_ANY, 0, &[])
    }

    /// "Add to an RRset" (RFC 2136 section 2.5.1): the zone's class, the RR's TTL and RDATA. A
    /// duplicate is silently ignored by the server.
    pub(super) fn add(
        &mut self,
        name: &DomainName,
        rtype: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Result<(), Error> {
        self.rr(1, name, rtype, CLASS_IN, ttl, rdata)
    }

    /// "Delete an RR from an RRset" (RFC 2136 section 2.5.4): class NONE, TTL 0, the RDATA of the
    /// one RR to delete. The server matches it by name, type and RDATA (section 3.4.2.4) and
    /// silently ignores an RR that does not exist. The TXT value operations use only this
    /// deletion; the deletion of a whole RRset ([`Builder::delete_rrset`]) is sent only by the
    /// record-level operations, under a prerequisite that names the RRset as read.
    pub(super) fn delete_rr(
        &mut self,
        name: &DomainName,
        rtype: u16,
        rdata: &[u8],
    ) -> Result<(), Error> {
        self.rr(1, name, rtype, CLASS_NONE, 0, rdata)
    }

    /// The finished message with message ID 0; [`Request::with_id`] sets the ID per attempt.
    pub(super) fn finish(self) -> Result<Request, Error> {
        let len = HEADER_LEN
            + self.question_wire.len()
            + self.sections.iter().map(Vec::len).sum::<usize>();
        if len > MAX_MESSAGE {
            return Err(invalid("the DNS message would exceed 65535 octets"));
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        // RFC 1035 section 4.1.1: QR 0, the opcode, AA/TC/RD 0, RCODE 0.
        let flags = u16::from(self.opcode & 0x0f) << 11;
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        for count in self.counts {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        bytes.extend_from_slice(&self.question_wire);
        for section in &self.sections {
            bytes.extend_from_slice(section);
        }
        Ok(Request {
            opcode: self.opcode,
            question: self.question,
            bytes,
        })
    }
}

/// A finished message without TSIG.
#[derive(Clone, Debug)]
pub(super) struct Request {
    /// The opcode.
    pub(super) opcode: u8,
    /// The question (the zone section of an update).
    pub(super) question: Question,
    /// The message with ID 0.
    bytes: Vec<u8>,
}

impl Request {
    /// The length of the message without TSIG.
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    /// A copy of the message with message ID `id`.
    pub(super) fn with_id(&self, id: u16) -> Vec<u8> {
        let mut out = self.bytes.clone();
        if let Some(slot) = out.get_mut(0..2) {
            slot.copy_from_slice(&id.to_be_bytes());
        }
        out
    }
}

/// Why a message could not be read. The text is a constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ParseError(pub(super) &'static str);

/// A cursor over a message. Every read checks its bounds.
pub(super) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(buf: &'a [u8], pos: usize) -> Reader<'a> {
        Reader { buf, pos }
    }

    pub(super) fn pos(&self) -> usize {
        self.pos
    }

    pub(super) fn bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ParseError("the message ends early"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(ParseError("the message ends early"))?;
        self.pos = end;
        Ok(slice)
    }

    pub(super) fn u16(&mut self) -> Result<u16, ParseError> {
        match self.bytes(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err(ParseError("the message ends early")),
        }
    }

    pub(super) fn u32(&mut self) -> Result<u32, ParseError> {
        match self.bytes(4)? {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(ParseError("the message ends early")),
        }
    }

    /// An unsigned 48-bit integer (the time of a TSIG record, RFC 8945 section 4.2).
    pub(super) fn u48(&mut self) -> Result<u64, ParseError> {
        Ok(self
            .bytes(6)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    /// A name, following compression pointers (RFC 1035 section 4.1.4). The text is lowercase
    /// with the trailing dot (`.` for the root) and escaped as `DomainName` spells names (design
    /// section 4.2: a dot inside a label as `\.`, a backslash as `\\`, `"`, `$`, `(`, `)`,
    /// `;`, `@`, space and octets outside 0x21-0x7E as `\DDD`), so a dot inside a label cannot
    /// pass for a label boundary and the text compares directly with `DomainName::as_str`.
    pub(super) fn name(&mut self) -> Result<String, ParseError> {
        let mut out = String::new();
        let mut pos = self.pos;
        let mut jumped = false;
        let mut pointers = 0usize;
        let mut wire_len = 0usize;
        loop {
            let len = *self
                .buf
                .get(pos)
                .ok_or(ParseError("the message ends inside a name"))?;
            match len & 0xc0 {
                0x00 => {
                    pos += 1;
                    wire_len += 1 + usize::from(len);
                    if wire_len > MAX_NAME {
                        return Err(ParseError("a name is longer than 255 octets"));
                    }
                    if len == 0 {
                        break;
                    }
                    let end = pos + usize::from(len);
                    let label = self
                        .buf
                        .get(pos..end)
                        .ok_or(ParseError("the message ends inside a name"))?;
                    for &b in label {
                        match b.to_ascii_lowercase() {
                            b'.' => out.push_str("\\."),
                            b'\\' => out.push_str("\\\\"),
                            b'"' | b'$' | b'(' | b')' | b';' | b'@' => {
                                out.push_str(&format!("\\{b:03}"));
                            }
                            c @ 0x21..=0x7e => out.push(char::from(c)),
                            _ => out.push_str(&format!("\\{b:03}")),
                        }
                    }
                    out.push('.');
                    pos = end;
                }
                0xc0 => {
                    let low = *self
                        .buf
                        .get(pos + 1)
                        .ok_or(ParseError("the message ends inside a name"))?;
                    if !jumped {
                        self.pos = pos + 2;
                        jumped = true;
                    }
                    pointers += 1;
                    if pointers > MAX_POINTERS {
                        return Err(ParseError("a name has a compression loop"));
                    }
                    pos = (usize::from(len & 0x3f) << 8) | usize::from(low);
                }
                _ => return Err(ParseError("a name has a reserved label type")),
            }
        }
        if !jumped {
            self.pos = pos;
        }
        if out.is_empty() {
            out.push('.');
        }
        Ok(out)
    }
}

/// One resource record of an answer, with the bounds of its RDATA in the buffer.
#[derive(Clone, Debug)]
pub(super) struct Record {
    /// Owner name in the spelling of [`Reader::name`].
    pub(super) name: String,
    pub(super) rtype: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Range<usize>,
    /// Where the record starts: for TSIG, the message before it is what the MAC covers.
    pub(super) start: usize,
}

/// A parsed answer.
#[derive(Clone, Debug)]
pub(super) struct Response {
    pub(super) id: u16,
    flags: u16,
    pub(super) questions: Vec<Question>,
    pub(super) answers: Vec<Record>,
    /// The authority section: the NS records of a referral (RFC 1034 section 4.3.2, step 3b).
    pub(super) authority: Vec<Record>,
    pub(super) additional: Vec<Record>,
}

impl Response {
    /// QR: this is a response.
    pub(super) fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub(super) fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    /// AA: the answer comes from an authority for the name.
    pub(super) fn authoritative(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    /// TC: the message was truncated.
    pub(super) fn truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// The four-bit RCODE of the header.
    pub(super) fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }
}

/// Parses a whole message. Trailing octets are an error.
pub(super) fn parse(buf: &[u8]) -> Result<Response, ParseError> {
    let mut r = Reader::new(buf, 0);
    let id = r.u16()?;
    let flags = r.u16()?;
    let qdcount = r.u16()?;
    let counts = [r.u16()?, r.u16()?, r.u16()?];
    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let name = r.name()?;
        let qtype = r.u16()?;
        let qclass = r.u16()?;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }
    let mut sections: [Vec<Record>; 3] = Default::default();
    for (section, count) in sections.iter_mut().zip(counts) {
        for _ in 0..count {
            let start = r.pos();
            let name = r.name()?;
            let rtype = r.u16()?;
            let class = r.u16()?;
            let ttl = r.u32()?;
            let len = usize::from(r.u16()?);
            let at = r.pos();
            r.bytes(len)?;
            section.push(Record {
                name,
                rtype,
                class,
                ttl,
                rdata: at..at + len,
                start,
            });
        }
    }
    if r.pos() != buf.len() {
        return Err(ParseError("the message has octets after its last record"));
    }
    let [answers, authority, additional] = sections;
    Ok(Response {
        id,
        flags,
        questions,
        answers,
        authority,
        additional,
    })
}

/// The data of TXT RDATA: its character-strings concatenated (RFC 1035 section 3.3.14). `None`
/// when the RDATA is empty or a length octet points past its end.
pub(super) fn txt_data(rdata: &[u8]) -> Option<Vec<u8>> {
    if rdata.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(rdata.len());
    let mut pos = 0usize;
    while pos < rdata.len() {
        let len = usize::from(*rdata.get(pos)?);
        out.extend_from_slice(rdata.get(pos + 1..pos + 1 + len)?);
        pos += 1 + len;
    }
    Some(out)
}

/// One field of RDATA that may hold a compressed name.
#[derive(Clone, Copy)]
enum Field {
    /// A fixed number of octets.
    Fixed(usize),
    /// A domain name, possibly compressed.
    Name,
    /// A character-string: a length octet and that many octets.
    CharString,
    /// Everything up to the end of the RDATA.
    Rest,
}

/// The RDATA layout of the types whose names a server may compress: the types of RFC 1035, which
/// a receiver MUST decompress, and RP, AFSDB, RT, SIG, PX, NXT, NAPTR and SRV, which it SHOULD
/// decompress (RFC 3597 section 4). Layouts: RFC 1035 section 3.3 (NS, MD, MF, CNAME, MB, MG,
/// MR, PTR: one name; SOA: two names and five 32-bit fields; MINFO: two names; MX: a 16-bit
/// preference and a name), RFC 1183 (RP: two names; AFSDB and RT: a 16-bit field and a name),
/// RFC 2535 sections 4.1 and 5.2 (SIG: 18 octets, the signer's name, the signature; NXT: a name
/// and a bit map), RFC 2163 section 4 (PX: a 16-bit preference and two names), RFC 2782 (SRV:
/// three 16-bit fields and a name), RFC 3403 section 4.1 (NAPTR: two 16-bit fields, three
/// character-strings and a name). Every other type is copied as it is: its names are never
/// compressed (RFC 3597 section 4).
fn layout(rtype: u16) -> Option<&'static [Field]> {
    use Field::{CharString, Fixed, Name, Rest};
    Some(match rtype {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 => &[Name],
        6 => &[Name, Name, Fixed(20)],
        14 | 17 => &[Name, Name],
        15 | 18 | 21 => &[Fixed(2), Name],
        24 => &[Fixed(18), Name, Rest],
        26 => &[Fixed(2), Name, Name],
        30 => &[Name, Rest],
        33 => &[Fixed(6), Name],
        35 => &[Fixed(4), CharString, CharString, CharString, Name],
        _ => return None,
    })
}

/// The RDATA of an answer record without name compression: the octets as the server sent them,
/// with every compressed name of the types in [`layout`] expanded, label octets unchanged. RDATA
/// that does not fit its type's layout is returned as it is; the record model then carries it
/// as non-canonical data.
pub(super) fn rdata_uncompressed(buf: &[u8], record: &Record) -> Result<Vec<u8>, ParseError> {
    let raw = buf
        .get(record.rdata.clone())
        .ok_or(ParseError("an answer record points outside the message"))?;
    let Some(fields) = layout(record.rtype) else {
        return Ok(raw.to_vec());
    };
    Ok(expand(buf, record.rdata.clone(), fields).unwrap_or_else(|| raw.to_vec()))
}

fn expand(buf: &[u8], rdata: Range<usize>, fields: &[Field]) -> Option<Vec<u8>> {
    let end = rdata.end;
    let mut pos = rdata.start;
    let mut out = Vec::with_capacity(end.saturating_sub(pos) + MAX_NAME);
    for field in fields {
        match *field {
            Field::Fixed(n) => {
                let next = pos.checked_add(n).filter(|&next| next <= end)?;
                out.extend_from_slice(buf.get(pos..next)?);
                pos = next;
            }
            Field::CharString => {
                let len = usize::from(*buf.get(pos).filter(|_| pos < end)?);
                let next = pos.checked_add(1 + len).filter(|&next| next <= end)?;
                out.extend_from_slice(buf.get(pos..next)?);
                pos = next;
            }
            Field::Name => pos = expand_name(buf, pos, end, &mut out)?,
            Field::Rest => {
                out.extend_from_slice(buf.get(pos..end)?);
                pos = end;
            }
        }
    }
    (pos == end).then_some(out)
}

/// Appends the name at `pos` uncompressed and returns the position after it within the RDATA
/// (which ends at `end`). A pointer must point backwards (RFC 1035 section 4.1.4: "a prior
/// occurance of the same name"), which also rules out loops.
fn expand_name(buf: &[u8], mut pos: usize, end: usize, out: &mut Vec<u8>) -> Option<usize> {
    let mut after: Option<usize> = None;
    let mut limit = end;
    let mut wire_len = 0usize;
    loop {
        let len = *buf.get(pos).filter(|_| pos < limit)?;
        match len & 0xc0 {
            0x00 => {
                wire_len += 1 + usize::from(len);
                if wire_len > MAX_NAME {
                    return None;
                }
                let next = pos
                    .checked_add(1 + usize::from(len))
                    .filter(|&n| n <= limit)?;
                out.extend_from_slice(buf.get(pos..next)?);
                if len == 0 {
                    return Some(after.unwrap_or(next));
                }
                pos = next;
            }
            0xc0 => {
                let low = *buf.get(pos + 1).filter(|_| pos + 1 < limit)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                if target >= pos {
                    return None;
                }
                after.get_or_insert(pos + 2);
                limit = pos;
                pos = target;
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dn(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[test]
    fn update_message_layout() {
        let mut b = Builder::update(&dn("Example.ORG"));
        b.add(&dn("_acme-challenge.example.org"), TYPE_TXT, 60, b"\x03abc")
            .unwrap();
        b.delete_rr(&dn("_acme-challenge.example.org"), TYPE_TXT, b"\x03old")
            .unwrap();
        let m = b.finish().unwrap().with_id(0x1234);
        // ID, opcode UPDATE, ZOCOUNT 1, PRCOUNT 0, UPCOUNT 2, ADCOUNT 0.
        assert_eq!(&m[..12], &[0x12, 0x34, 0x28, 0, 0, 1, 0, 0, 0, 2, 0, 0]);
        assert_eq!(&m[12..25], b"\x07example\x03org\x00");
        assert_eq!(&m[25..29], &[0, 6, 0, 1]);
        let p = parse(&m).unwrap();
        assert_eq!(
            (p.id, p.opcode(), p.is_response()),
            (0x1234, OPCODE_UPDATE, false)
        );
        let mut r = Reader::new(&m, 29);
        assert_eq!(r.name().unwrap(), "_acme-challenge.example.org.");
        assert_eq!((r.u16().unwrap(), r.u16().unwrap()), (TYPE_TXT, CLASS_IN));
        assert_eq!(r.u32().unwrap(), 60);
        let mut r = Reader::new(&m, 29 + 29 + 10 + 4);
        assert_eq!(r.name().unwrap(), "_acme-challenge.example.org.");
        assert_eq!((r.u16().unwrap(), r.u16().unwrap()), (TYPE_TXT, CLASS_NONE));
        assert_eq!(r.u32().unwrap(), 0);
    }

    #[test]
    fn query_and_prerequisite_layout() {
        let q = Builder::query(&dn("a.example.org"), TYPE_TXT)
            .finish()
            .unwrap()
            .with_id(1);
        assert_eq!(&q[2..12], &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut b = Builder::update(&dn("example.org"));
        b.prereq_name_in_use(&dn("example.org")).unwrap();
        let m = b.finish().unwrap().with_id(2);
        assert_eq!(&m[4..12], &[0, 1, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            &m[29..],
            b"\x07example\x03org\x00\x00\xff\x00\xff\0\0\0\0\0\0"
        );
        let root = Builder::query(&DomainName::root(), TYPE_SOA)
            .finish()
            .unwrap()
            .with_id(3);
        assert_eq!(&root[12..], &[0, 0, 6, 0, 1]);
    }

    #[test]
    fn oversized_messages_are_refused() {
        let mut b = Builder::update(&dn("example.org"));
        let rdata = vec![0u8; 65_535];
        b.add(&dn("example.org"), TYPE_TXT, 1, &rdata).unwrap();
        assert!(b.finish().is_err());
        let mut b = Builder::update(&dn("example.org"));
        assert!(
            b.add(&dn("example.org"), TYPE_TXT, 1, &vec![0u8; 65_536])
                .is_err()
        );
    }

    #[test]
    fn names_with_compression_loops_and_odd_octets() {
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(b"\x07example\x03org\x00");
        buf.extend_from_slice(&[0x03, b'W', b'w', b'w', 0xc0, 12]);
        let mut r = Reader::new(&buf, 25);
        assert_eq!(r.name().unwrap(), "www.example.org.");
        assert_eq!(r.pos(), 31);
        assert!(Reader::new(&[0xc0u8, 0], 0).name().is_err());
        assert!(Reader::new(&[0x05, b'a'], 0).name().is_err());
        assert!(Reader::new(&[0x40], 0).name().is_err());
        assert!(Reader::new(&[0xc0], 0).name().is_err());
        assert_eq!(
            Reader::new(b"\x03a.b\x03org\x00", 0).name().unwrap(),
            "a\\.b.org."
        );
        // The spelling of `DomainName`, so the two compare directly.
        assert_eq!(
            Reader::new(b"\x03a b\x03A/c\x00", 0).name().unwrap(),
            "a\\032b.a/c."
        );
        assert_eq!(Reader::new(&[0], 0).name().unwrap(), ".");
        // 128 labels of one octet: 257 octets in wire form.
        let mut long = Vec::new();
        for _ in 0..128 {
            long.extend_from_slice(b"\x01a");
        }
        long.push(0);
        assert!(Reader::new(&long, 0).name().is_err());
    }

    #[test]
    fn parse_refuses_truncated_and_trailing_data() {
        let m = Builder::query(&dn("a.example.org"), TYPE_TXT)
            .finish()
            .unwrap()
            .with_id(1);
        for cut in 0..m.len() {
            assert!(parse(&m[..cut]).is_err(), "{cut}");
        }
        let mut longer = m.clone();
        longer.push(0);
        assert!(parse(&longer).is_err());
        // A count far larger than the data fails without panicking.
        let mut huge = m;
        huge[6] = 0xff;
        huge[7] = 0xff;
        assert!(parse(&huge).is_err());
    }

    #[test]
    fn rdata_names_are_decompressed() {
        // Header, question `www.example.org. A IN`, then an answer `CNAME` whose target
        // `host.example.org.` points to `example.org.` in the question.
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(b"\x03www\x07Example\x03org\x00\x00\x01\x00\x01");
        let rdata_at = buf.len();
        buf.extend_from_slice(&[0x04, b'H', b'o', b's', b't', 0xc0, 16]);
        let record = Record {
            name: "www.example.org.".to_owned(),
            rtype: TYPE_CNAME,
            class: CLASS_IN,
            ttl: 60,
            rdata: rdata_at..buf.len(),
            start: rdata_at,
        };
        assert_eq!(
            rdata_uncompressed(&buf, &record).unwrap(),
            b"\x04Host\x07Example\x03org\x00"
        );
        // MX: the preference stays, the exchange is expanded.
        let mx_at = buf.len();
        buf.extend_from_slice(&[0, 10, 0xc0, 12]);
        let mx = Record {
            rtype: 15,
            rdata: mx_at..buf.len(),
            ..record.clone()
        };
        assert_eq!(
            rdata_uncompressed(&buf, &mx).unwrap(),
            b"\x00\x0a\x03www\x07Example\x03org\x00"
        );
        // A forward pointer, a pointer to itself and RDATA longer than its fields are kept as
        // they are, never followed into a loop.
        for bad in [&[0xc0u8, 0xff][..], &[0x01, b'a', 0x00, 0x00][..]] {
            let at = buf.len();
            buf.extend_from_slice(bad);
            let record = Record {
                rdata: at..buf.len(),
                ..record.clone()
            };
            assert_eq!(rdata_uncompressed(&buf, &record).unwrap(), bad);
        }
        let at = buf.len();
        buf.extend_from_slice(&[0xc0, u8::try_from(at).unwrap()]);
        let looped = Record {
            rdata: at..buf.len(),
            ..record.clone()
        };
        assert_eq!(rdata_uncompressed(&buf, &looped).unwrap(), &buf[at..]);
        // A type without names inside its RDATA is copied, pointer-like octets included.
        let a = Record {
            rtype: 1,
            rdata: rdata_at..rdata_at + 4,
            ..record
        };
        assert_eq!(
            rdata_uncompressed(&buf, &a).unwrap(),
            &buf[rdata_at..rdata_at + 4]
        );
    }

    #[test]
    fn rrset_deletion_never_names_every_type() {
        let mut b = Builder::update(&dn("example.org"));
        assert!(b.delete_rrset(&dn("a.example.org"), TYPE_ANY).is_err());
        b.delete_rrset(&dn("a.example.org"), TYPE_TXT).unwrap();
        b.prereq_rr(&dn("a.example.org"), TYPE_TXT, b"\x01x")
            .unwrap();
        b.prereq_name_unused(&dn("a.example.org")).unwrap();
        let m = b.finish().unwrap().with_id(1);
        let p = parse(&m).unwrap();
        // PRCOUNT 2, UPCOUNT 1.
        assert_eq!(&m[4..12], &[0, 1, 0, 2, 0, 1, 0, 0]);
        let mut r = Reader::new(&m, 29);
        r.name().unwrap();
        assert_eq!(
            (r.u16().unwrap(), r.u16().unwrap(), r.u32().unwrap()),
            (TYPE_TXT, CLASS_IN, 0)
        );
        assert_eq!(p.answers.len(), 2);
        assert_eq!(
            (p.answers[1].rtype, p.answers[1].class),
            (TYPE_ANY, CLASS_NONE)
        );
        assert_eq!(p.authority.len(), 1);
        let rrset = &p.authority[0];
        assert_eq!(
            (rrset.rtype, rrset.class, rrset.ttl),
            (TYPE_TXT, CLASS_ANY, 0)
        );
        assert!(rrset.rdata.is_empty());
    }

    #[test]
    fn txt_data_reads_character_strings() {
        assert_eq!(txt_data(b"\x02ab\x01c").unwrap(), b"abc");
        assert_eq!(txt_data(b"\x00").unwrap(), b"");
        assert_eq!(txt_data(b"\x05ab"), None);
        assert_eq!(txt_data(b""), None);
    }
}
