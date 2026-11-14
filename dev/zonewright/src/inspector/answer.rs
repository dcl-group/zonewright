//! Values and classification (design sections 8.4 and 8.5): answer records become
//! [`RecordData`], and a [`Reply`] becomes an [`Answer`].

use std::collections::BTreeSet;

use hickory_proto::rr::RData;

use super::Answer;
use super::exchange::{Ask, Failure, Reply, ReplyRecord, bounded, name_to_wire};
use crate::name::TargetName;
use crate::record::{RecordData, RecordType, Ttl};

/// Most CNAME links followed inside one resolver answer.
pub(crate) const MAX_ANSWER_CNAME_LINKS: usize = 8;

const NOERROR: u16 = 0;
const SERVFAIL: u16 = 2;
const NXDOMAIN: u16 = 3;
const REFUSED: u16 = 5;
const CNAME: u16 = 5;

/// Converts one answer record into canonical [`RecordData`].
///
/// For the types whose RDATA may contain compressed names (NS, CNAME, PTR, MX, SOA, SRV) the
/// fields come from the decoded message and are written back in uncompressed form; for every
/// other type, including types the codec does not know, the raw RDATA is used. Both go through
/// `RecordData::from_wire`, the one definition of each canonical form. The error text never
/// quotes the data.
pub(crate) fn convert_record(data: &RData, rtype: u16, raw: &[u8]) -> Result<RecordData, String> {
    let mut wire = Vec::new();
    let rdata: &[u8] = match data {
        RData::NS(name) => {
            wire.extend_from_slice(&name_to_wire(&name.0));
            &wire
        }
        RData::CNAME(name) => {
            wire.extend_from_slice(&name_to_wire(&name.0));
            &wire
        }
        RData::PTR(name) => {
            wire.extend_from_slice(&name_to_wire(&name.0));
            &wire
        }
        RData::MX(mx) => {
            wire.extend_from_slice(&mx.preference.to_be_bytes());
            wire.extend_from_slice(&name_to_wire(&mx.exchange));
            &wire
        }
        RData::SRV(srv) => {
            wire.extend_from_slice(&srv.priority.to_be_bytes());
            wire.extend_from_slice(&srv.weight.to_be_bytes());
            wire.extend_from_slice(&srv.port.to_be_bytes());
            wire.extend_from_slice(&name_to_wire(&srv.target));
            &wire
        }
        RData::SOA(soa) => {
            wire.extend_from_slice(&name_to_wire(&soa.mname));
            wire.extend_from_slice(&name_to_wire(&soa.rname));
            wire.extend_from_slice(&soa.serial.to_be_bytes());
            // The interval fields are unsigned 32-bit on the wire; the codec keeps them as i32.
            wire.extend_from_slice(&soa.refresh.to_be_bytes());
            wire.extend_from_slice(&soa.retry.to_be_bytes());
            wire.extend_from_slice(&soa.expire.to_be_bytes());
            wire.extend_from_slice(&soa.minimum.to_be_bytes());
            &wire
        }
        _ => raw,
    };
    RecordData::from_wire(RecordType::from_code(rtype), rdata)
        .map_err(|err| bounded(&err.to_string()))
}

/// How an answer is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// A name server asked with recursion not desired: AA is required, a CNAME is reported.
    Server,
    /// A resolver asked with recursion desired: AA is not required. With `follow`, a CNAME
    /// chain inside the answer is followed to the records of the asked type.
    Resolver {
        /// Follow a CNAME chain inside the answer.
        follow: bool,
    },
}

/// Maps the outcome of one exchange to an [`Answer`].
pub(crate) fn classify(outcome: Result<Reply, Failure>, ask: &Ask, mode: Mode) -> Answer {
    match outcome {
        Ok(reply) => classify_reply(&reply, ask, mode),
        Err(Failure::Timeout) => Answer::Timeout,
        Err(Failure::Network(detail) | Failure::Malformed(detail)) => Answer::Failed(detail),
    }
}

fn classify_reply(reply: &Reply, ask: &Ask, mode: Mode) -> Answer {
    match reply.rcode {
        NOERROR | NXDOMAIN => {}
        REFUSED => return Answer::Refused,
        SERVFAIL => return Answer::ServFail,
        other => return Answer::Failed(format!("response code {other}")),
    }
    if mode == Mode::Server && !reply.authoritative {
        return Answer::NotAuthoritative;
    }
    let follow = matches!(mode, Mode::Resolver { follow: true });
    let mut current: Vec<u8> = ask.name.clone();
    let mut seen: Vec<Vec<u8>> = vec![current.clone()];
    loop {
        let records: Vec<&ReplyRecord> = reply
            .records
            .iter()
            .filter(|record| record.owner == current && record.rtype == ask.rtype)
            .collect();
        // RFC 6604: the response code describes the last name of a chain. An NXDOMAIN from a
        // name server for a name that is itself a CNAME is reported as that CNAME, below.
        let nxdomain_here = reply.rcode == NXDOMAIN && mode == Mode::Server;
        if !records.is_empty() && !nxdomain_here {
            return rrset(&records);
        }
        if ask.rtype == CNAME {
            break;
        }
        let target = match cname_at(reply, &current) {
            Ok(Some(target)) => target,
            Ok(None) => break,
            Err(detail) => return Answer::Failed(detail),
        };
        if !follow {
            return Answer::Cname(target);
        }
        if seen.len() > MAX_ANSWER_CNAME_LINKS {
            return Answer::Failed(format!(
                "the CNAME chain in the answer is longer than {MAX_ANSWER_CNAME_LINKS} links"
            ));
        }
        current = target.wire().to_vec();
        if seen.contains(&current) {
            return Answer::Failed("the CNAME chain in the answer loops".to_owned());
        }
        seen.push(current.clone());
    }
    if reply.rcode == NXDOMAIN {
        Answer::NxDomain
    } else {
        Answer::NoData
    }
}

/// The target of the CNAME owned by `owner`, if the answer has one. More than one distinct
/// target is malformed.
fn cname_at(reply: &Reply, owner: &[u8]) -> Result<Option<TargetName>, String> {
    let mut found: Option<TargetName> = None;
    for record in reply
        .records
        .iter()
        .filter(|record| record.owner == owner && record.rtype == CNAME)
    {
        let data = record.data.as_ref().map_err(Clone::clone)?;
        let target = TargetName::parse(data.as_str())
            .map_err(|_| "a CNAME target could not be read".to_owned())?;
        match &found {
            Some(existing) if *existing != target => {
                return Err("the answer holds more than one CNAME for the name".to_owned());
            }
            _ => found = Some(target),
        }
    }
    Ok(found)
}

/// The rrset of the matching records: values deduplicated and sorted, the smallest TTL.
fn rrset(records: &[&ReplyRecord]) -> Answer {
    let mut values: BTreeSet<RecordData> = BTreeSet::new();
    let mut ttl = u32::MAX;
    for record in records {
        match &record.data {
            Ok(data) => {
                values.insert(data.clone());
            }
            Err(detail) => return Answer::Failed(detail.clone()),
        }
        ttl = ttl.min(record.ttl);
    }
    // RFC 2181 section 8: a TTL with the most significant bit set is treated as zero.
    let secs = if ttl > Ttl::MAX.as_secs() { 0 } else { ttl };
    let ttl = match Ttl::from_secs(secs) {
        Ok(ttl) => ttl,
        Err(err) => return Answer::Failed(bounded(&err.to_string())),
    };
    Answer::Records {
        ttl,
        records: values.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::testing::{data, rec, reply, wire};

    fn ask(name: &str, rtype: RecordType) -> Ask {
        Ask {
            name: wire(name),
            rtype: rtype.code().unwrap(),
            recursion: false,
        }
    }

    const SERVER: Mode = Mode::Server;
    const RESOLVER: Mode = Mode::Resolver { follow: true };

    #[test]
    fn response_codes_and_the_aa_flag_come_first() {
        let q = ask("a.example.org", RecordType::TXT);
        let txt = rec("a.example.org", RecordType::TXT, 60, "\"v\"");
        let c = |r: Reply, m| classify(Ok(r), &q, m);
        assert_eq!(c(reply(5, true, vec![]), SERVER), Answer::Refused);
        assert_eq!(c(reply(2, true, vec![]), SERVER), Answer::ServFail);
        assert_eq!(
            c(reply(4, true, vec![]), SERVER),
            Answer::Failed("response code 4".into())
        );
        assert_eq!(
            c(reply(0, false, vec![txt.clone()]), SERVER),
            Answer::NotAuthoritative
        );
        assert_eq!(c(reply(3, false, vec![]), SERVER), Answer::NotAuthoritative);
        assert_eq!(c(reply(3, true, vec![]), SERVER), Answer::NxDomain);
        // A resolver needs no AA.
        assert!(matches!(
            c(reply(0, false, vec![txt]), RESOLVER),
            Answer::Records { .. }
        ));
        assert_eq!(classify(Err(Failure::Timeout), &q, SERVER), Answer::Timeout);
        assert_eq!(
            classify(Err(Failure::Network("x".into())), &q, SERVER),
            Answer::Failed("x".into())
        );
    }

    #[test]
    fn records_are_the_asked_type_at_the_asked_name_deduplicated_with_the_smallest_ttl() {
        let q = ask("a.example.org", RecordType::TXT);
        let records = vec![
            rec("a.example.org", RecordType::TXT, 300, "\"b\""),
            rec("A.EXAMPLE.ORG", RecordType::TXT, 60, "\"a\"").clone(),
            rec("a.example.org", RecordType::TXT, 120, "\"b\""),
            rec("other.example.org", RecordType::TXT, 1, "\"smuggled\""),
            rec("a.example.org", RecordType::A, 1, "192.0.2.1"),
        ];
        let mut records = records;
        // Owners arrive lowercased from the transport; emulate that for the uppercase one.
        records[1].owner = wire("a.example.org");
        let answer = classify(Ok(reply(0, true, records)), &q, SERVER);
        assert_eq!(
            answer,
            Answer::Records {
                ttl: Ttl::from_secs(60).unwrap(),
                records: vec![
                    data(RecordType::TXT, "\"a\""),
                    data(RecordType::TXT, "\"b\"")
                ],
            }
        );
    }

    #[test]
    fn a_ttl_with_the_high_bit_set_is_zero() {
        let q = ask("a.example.org", RecordType::A);
        let mut r = rec("a.example.org", RecordType::A, 0, "192.0.2.1");
        r.ttl = 0x8000_0000;
        let answer = classify(Ok(reply(0, true, vec![r])), &q, SERVER);
        assert!(matches!(answer, Answer::Records { ttl, .. } if ttl.as_secs() == 0));
    }

    #[test]
    fn a_name_server_reports_a_cname_and_nodata() {
        let q = ask("a.example.org", RecordType::TXT);
        let cname = rec("a.example.org", RecordType::CNAME, 60, "b.example.net.");
        let target = TargetName::parse("b.example.net.").unwrap();
        assert_eq!(
            classify(Ok(reply(0, true, vec![cname.clone()])), &q, SERVER),
            Answer::Cname(target.clone())
        );
        // RFC 6604: NXDOMAIN after a CNAME describes the target; the name is a CNAME.
        assert_eq!(
            classify(Ok(reply(3, true, vec![cname.clone()])), &q, SERVER),
            Answer::Cname(target)
        );
        // Asking for the CNAME itself gives the record.
        let q_cname = ask("a.example.org", RecordType::CNAME);
        assert!(matches!(
            classify(Ok(reply(0, true, vec![cname])), &q_cname, SERVER),
            Answer::Records { .. }
        ));
        assert_eq!(
            classify(Ok(reply(0, true, vec![])), &q, SERVER),
            Answer::NoData
        );
        // A CNAME at another owner is ignored.
        let foreign = rec("x.example.org", RecordType::CNAME, 60, "b.example.net.");
        assert_eq!(
            classify(Ok(reply(0, true, vec![foreign])), &q, SERVER),
            Answer::NoData
        );
    }

    #[test]
    fn only_malformed_records_that_matter_fail_the_answer() {
        let q = ask("a.example.org", RecordType::TXT);
        let bad = |owner: &str, rtype: RecordType| ReplyRecord {
            owner: wire(owner),
            rtype: rtype.code().unwrap(),
            ttl: 60,
            data: Err("invalid record data: broken".into()),
        };
        let good = rec("a.example.org", RecordType::TXT, 60, "\"v\"");
        let answer = classify(
            Ok(reply(
                0,
                true,
                vec![good.clone(), bad("b.example.org", RecordType::TXT)],
            )),
            &q,
            SERVER,
        );
        assert!(matches!(answer, Answer::Records { .. }));
        let answer = classify(
            Ok(reply(
                0,
                true,
                vec![good, bad("a.example.org", RecordType::TXT)],
            )),
            &q,
            SERVER,
        );
        assert_eq!(answer, Answer::Failed("invalid record data: broken".into()));
    }

    #[test]
    fn a_resolver_answer_is_followed_through_its_cname_chain() {
        let q = ask("a.example.org", RecordType::TXT);
        let records = vec![
            rec("c.example.net", RecordType::TXT, 30, "\"end\""),
            rec("a.example.org", RecordType::CNAME, 60, "b.example.net."),
            rec("b.example.net", RecordType::CNAME, 60, "c.example.net."),
        ];
        assert_eq!(
            classify(Ok(reply(0, false, records.clone())), &q, RESOLVER),
            Answer::Records {
                ttl: Ttl::from_secs(30).unwrap(),
                records: vec![data(RecordType::TXT, "\"end\"")],
            }
        );
        // Without following, the first link is the answer.
        assert_eq!(
            classify(
                Ok(reply(0, false, records)),
                &q,
                Mode::Resolver { follow: false }
            ),
            Answer::Cname(TargetName::parse("b.example.net.").unwrap())
        );
        // A chain that ends without data.
        let records = vec![rec(
            "a.example.org",
            RecordType::CNAME,
            60,
            "b.example.net.",
        )];
        assert_eq!(
            classify(Ok(reply(0, false, records.clone())), &q, RESOLVER),
            Answer::NoData
        );
        assert_eq!(
            classify(Ok(reply(3, false, records)), &q, RESOLVER),
            Answer::NxDomain
        );
    }

    fn chain(links: usize) -> Vec<ReplyRecord> {
        let mut records = Vec::new();
        for i in 0..links {
            let owner = if i == 0 {
                "start.example.org".to_owned()
            } else {
                format!("n{i}.example.org")
            };
            records.push(rec(
                &owner,
                RecordType::CNAME,
                60,
                &format!("n{}.example.org.", i + 1),
            ));
        }
        records.push(rec(
            &format!("n{links}.example.org"),
            RecordType::A,
            60,
            "192.0.2.9",
        ));
        records
    }

    #[test]
    fn a_chain_inside_an_answer_is_bounded_and_loops_are_refused() {
        let q = ask("start.example.org", RecordType::A);
        assert!(matches!(
            classify(Ok(reply(0, false, chain(8))), &q, RESOLVER),
            Answer::Records { .. }
        ));
        assert!(matches!(
            classify(Ok(reply(0, false, chain(9))), &q, RESOLVER),
            Answer::Failed(detail) if detail.contains("longer than 8")
        ));
        let looping = vec![
            rec("start.example.org", RecordType::CNAME, 60, "b.example.org."),
            rec("b.example.org", RecordType::CNAME, 60, "start.example.org."),
        ];
        assert!(matches!(
            classify(Ok(reply(0, false, looping)), &q, RESOLVER),
            Answer::Failed(detail) if detail.contains("loops")
        ));
        let two = vec![
            rec("start.example.org", RecordType::CNAME, 60, "b.example.org."),
            rec("start.example.org", RecordType::CNAME, 60, "c.example.org."),
        ];
        assert!(matches!(
            classify(Ok(reply(0, false, two)), &q, RESOLVER),
            Answer::Failed(_)
        ));
    }

    #[test]
    fn compressed_name_types_are_rebuilt_from_decoded_fields() {
        use hickory_proto::rr::Name;
        use hickory_proto::rr::rdata::{MX, SOA, SRV};
        let name = |s: &str| Name::from_ascii(s).unwrap();
        let mx = RData::MX(MX::new(10, name("Mail.Example.ORG.")));
        assert_eq!(
            convert_record(&mx, 15, &[0xc0, 0x0c]).unwrap(),
            data(RecordType::MX, "10 mail.example.org.")
        );
        let srv = RData::SRV(SRV::new(0, 5, 443, name("t.example.org.")));
        assert_eq!(
            convert_record(&srv, 33, &[]).unwrap(),
            data(RecordType::SRV, "0 5 443 t.example.org.")
        );
        let soa = RData::SOA(SOA::new(
            name("ns.example.org."),
            name("host.example.org."),
            7,
            -1,
            2,
            3,
            4,
        ));
        assert_eq!(
            convert_record(&soa, 6, &[]).unwrap(),
            data(
                RecordType::SOA,
                "ns.example.org. host.example.org. 7 4294967295 2 3 4"
            )
        );
        // Everything else goes through the raw RDATA.
        let raw = [192u8, 0, 2, 1];
        let a = RData::A(hickory_proto::rr::rdata::A::new(10, 0, 0, 1));
        assert_eq!(
            convert_record(&a, 1, &raw).unwrap(),
            data(RecordType::A, "192.0.2.1")
        );
        assert!(convert_record(&a, 1, &[1, 2, 3]).is_err());
    }
}
