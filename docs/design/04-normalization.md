# zonewright design: Record value normalization

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 4. Record value normalization

Decision 9: values are zone-file text (RFC 1035 section 5) in one canonical spelling per type, so a
value read from a provider and a value seen on the wire by the inspector are equal as `RecordData`
exactly when they are the same record.

### 4.1 General rules

- Canonical text is ASCII. Fields are separated by exactly one space; there is no leading or
  trailing whitespace, no comment, no parentheses, no `$` directive.
- Parsing accepts any run of spaces and tabs between fields, and leading and trailing whitespace. It
  rejects parentheses, comments and line breaks.
- Decimal integers are written without sign and without leading zeros. Parsing accepts leading zeros
  and rejects values outside the field's range (`OutOfRange`).
- Hexadecimal data is written lowercase without spaces. Parsing accepts either case and whitespace
  between groups.
- Base64 data (the SVCB `ech` parameter) is written in the standard alphabet with padding, without
  spaces. Parsing does not accept whitespace inside the value.
- The comparison rule: two `RecordData` are equal iff their text is byte-for-byte equal. Two rrsets
  have the same records iff their sorted, deduplicated member lists are equal. There is no
  type-aware comparison beyond canonicalization, so the rule is the same in the crate, in an
  application's database and in a test.

### 4.2 Domain names inside RDATA

Applies to NS, CNAME, PTR, DNAME, the pseudo-types ALIAS and ANAME, the exchange of MX, the target
of SRV and SVCB/HTTPS, and both names of SOA. These are `TargetName` values (section 2.1), not
`DomainName`: a zone may point at any name DNS can express, and the crate has to carry it and
compare it, whether or not it could be an owner name here.

One rule, used for provider text and for wire data alike:

- A name is a sequence of labels, each 1 to 63 octets, at most 255 octets in wire form, always
  absolute. The root is `.` (SRV "service not available", null MX, SVCB "same as owner").
- Canonical text: labels joined by `.`, with a trailing dot. ASCII letters are lowercased; no other
  octet is changed. Inside a label, the octets `a`–`z`, `0`–`9`, `-`, `_`, `*`, `/` and every other
  printable ASCII octet except those named next are written as themselves; a dot is written `\.` and
  a backslash `\\`; and `"`, `$`, `(`, `)`, `;`, `@`, space and every octet outside 0x21–0x7E are
  written `\DDD` with three decimal digits.
- Parsing text accepts `\DDD` (value at most 255) and `\X` for any other character `X`, in addition
  to literal characters. A `\` followed by one or two digits, or at the end, is `BadEscape`. Text
  with non-ASCII characters is first converted with IDNA to A-labels, since a U-label is a display
  form of an A-label; if that conversion fails the parse fails.
- `RecordData::parse` treats a name without a trailing dot as absolute, because that is how nearly
  every provider API spells an absolute name; `@` is rejected. `RecordData::parse_relative` applies
  zone-file semantics with an origin; clients use it for providers that return names relative to the
  zone.
- From the wire, the labels are taken as they are and lowercased. No valid wire name fails to
  convert, so an unusual target never turns an inspector answer into a failure, and the text built
  from the wire equals the text built from a provider's spelling of the same name.

The earlier record-level implementation lowercased the whole value and stripped trailing dots. That
left relative and absolute spellings unequal and turned the SRV value `0 0 0 .` into text with a
trailing space; both are closed by parsing fields instead of editing strings.

### 4.3 Canonical form per type

| Type                                | Canonical text                                                         | Notes                                                                                                                                                 |
| ----------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| A                                   | `192.0.2.1`                                                            | Four decimal octets. Leading zeros are a syntax error (they read as octal elsewhere)                                                                  |
| AAAA                                | `2001:db8::1`                                                          | RFC 5952: lowercase, longest zero run compressed. IPv4-mapped addresses as `::ffff:192.0.2.1`                                                         |
| NS, CNAME, PTR, DNAME, ALIAS, ANAME | `host.example.org.`                                                    | One name (section 4.2)                                                                                                                                |
| MX                                  | `10 mail.example.org.`                                                 | Preference `u16`, then a name                                                                                                                         |
| SRV                                 | `0 5 443 host.example.org.`                                            | Priority, weight, port (`u16` each), then a name                                                                                                      |
| TXT                                 | `"v=spf1 mx -all"`                                                     | Section 4.4                                                                                                                                           |
| CAA                                 | `0 issue "ca.example.net"`                                             | Section 4.5                                                                                                                                           |
| TLSA                                | `3 1 1 0a1b…`                                                          | Usage, selector, matching type (`u8` each), then hex. At least one data octet                                                                         |
| SSHFP                               | `4 2 0a1b…`                                                            | Algorithm, fingerprint type (`u8` each), then hex                                                                                                     |
| SVCB, HTTPS                         | `1 . alpn="h2,h3" port=8443`                                           | Section 4.6                                                                                                                                           |
| SOA                                 | `ns1.example.org. admin.example.org. 2026111401 7200 3600 1209600 300` | Two names, then serial and four times (`u32` each). Time-unit suffixes (`1h`) are accepted for the four times, not the serial, and written as seconds |
| any other code                      | `\# 4 0a000001`                                                        | RFC 3597 (section 4.7)                                                                                                                                |

### 4.4 TXT

Model: the value of a TXT record is one byte string, the concatenation of its character-strings.
Where the boundaries between character-strings fall is not part of the value. Provider APIs split,
join and re-split long values on their own, so a form that kept the boundaries could not compare
equal across providers or against the wire. The cost is stated in section 13.4.

Canonical text:

- The bytes are cut into chunks of 255 octets; the last chunk holds the remainder. Empty data is one
  empty chunk.
- Each chunk is written between double quotes; chunks are separated by one space.
- Inside the quotes: `"` is written `\"`, `\` is written `\\`, bytes 0x20 to 0x7E are written as
  themselves, every other byte is written `\DDD` with three decimal digits. A multi-byte UTF-8
  character is therefore several `\DDD` groups, and a chunk boundary may fall inside it.

`RecordData::parse(RecordType::TXT, text)` accepts:

- one or more quoted strings separated by optional whitespace (`"a" "b"`, `"a""b"`), with the
  escapes `\DDD` (value at most 255) and `\X` for any other character `X`, and raw non-ASCII
  characters taken as their UTF-8 bytes; a quoted string longer than 255 octets is accepted and
  re-chunked;
- or exactly one unquoted token without whitespace, with the same escapes.

It rejects unquoted text that contains whitespace. Zone-file syntax would read `v=spf1 mx -all` as
three character-strings and join them into `v=spf1mx-all`; whoever wrote it meant one string with
spaces. Rejecting the ambiguous form removes the trap. A caller with a plain string uses
`Txt::new("v=spf1 mx -all")?.to_data()`.

Provider dialects. Clients do not pass TXT through `RecordData::parse` blindly, because providers
disagree on what the text in their API means. Each client declares one reading rule and one writing
rule from this private set, and the provider table records which:

- `Presentation`: the API carries zone-file text as above. Read with the strict parser; write the
  canonical text.
- `Raw`: the API carries the value itself, unquoted and unescaped. Read the string's bytes as the
  data; write the data as a string. A value that is not valid UTF-8, or that the provider is not
  known to accept unchanged, cannot be written and is `InvalidInput`.
- `Auto` (read only): text that starts with `"` is read as `Presentation`, anything else as `Raw`.
  For APIs observed or documented to return both spellings.

Two clients read by a rule of their own, shared by their record level and their TXT value operations
so that both agree on what a record holds: Selectel v2 reads only quoted content, as `Presentation`,
and Yandex Cloud reads the master-file strings its documentation names (section 11.2).

Until a source establishes how a provider treats quotes, backslashes, spaces and non-ASCII bytes in
TXT, its client sets `txt_plain_only` and accepts only `Txt::is_plain` values in the TXT value
operations. Plain values are spelled the same in every dialect apart from the surrounding quotes, so
no client has to guess an escaping rule (hard rule 3).

Gaps of the earlier implementations closed here: no escape handling on read or write (a `\"` inside
a value flipped the quote state; `"` and `\` were written raw), text after the last closing quote
silently dropped, unquoted text with embedded quotes passed through, chunking that could not round
trip values containing quotes, and comparison by string equality of provider text in the paths that
select a value to change.

### 4.5 CAA

`<flags> <tag> "<value>"`:

- flags: `u8` decimal;
- tag: 1 to 255 characters of `[a-z0-9]`, written lowercase; parsing accepts uppercase (RFC 8659
  section 4.1: tags are matched case-insensitively);
- value: always written as one quoted string with the escapes of section 4.4 and no length limit
  other than the RDATA size; parsing accepts a quoted or an unquoted value. The value is not
  case-folded and not interpreted.

### 4.6 SVCB and HTTPS

`<priority> <target> [<param> ...]` (RFC 9460 section 2.1):

- priority `u16`; target a name. Parameters are kept as given in both modes; alias mode (priority 0)
  normally has none.
- Parameters are written in ascending order of their numeric key, each once. Duplicate keys are a
  syntax error.
- Keys are written by name where RFC 9460 defines one (`mandatory`, `alpn`, `no-default-alpn`,
  `port`, `ipv4hint`, `ech`, `ipv6hint`) and as `key<number>` otherwise. Parsing accepts both forms
  for a defined key.
- Values: `mandatory` is a comma-separated list of key names in ascending numeric order; `alpn` is
  written quoted, comma-separated in the given order, with `,` and `\` inside an identifier escaped
  as RFC 9460 appendix A.1 prescribes; `no-default-alpn` has no value; `port` is decimal; `ipv4hint`
  and `ipv6hint` are comma-separated addresses in the canonical forms of section 4.3, in the given
  order; `ech` is base64; `key<number>` values are written as one quoted string with the escapes of
  section 4.4.

### 4.7 Unknown types

For a type code without a row in section 4.3 the only accepted and the canonical form is the generic
one of RFC 3597 section 5: `\# <length> <hex>`, length in decimal, hex lowercase without spaces,
`\# 0` for empty RDATA.

For a type that has a row, the generic form is accepted on input and converted: the wire data is
decoded and written in the type's own canonical form. So `\# 4 c0000201` for type A is the same
`RecordData` as `192.0.2.1`. The pseudo-types ALIAS and ANAME have no generic form.

A provider that returns its own text for a type the crate has no row for cannot be normalized: the
value is carried as non-canonical data (section 4.9) and will not compare equal to what the
inspector sees for the same record. Adding a row for a type fixes that for the type; it changes the
canonical text of that type's values and is called out in the changelog.

### 4.8 Wire conversion

`RecordData::from_wire` and `to_wire` implement the RDATA formats of the types in section 4.3 (RFC
1035, 3596, 2782, 8659, 6698, 4255, 9460, 6672). `from_wire` takes uncompressed RDATA; a compression
pointer is a syntax error. TXT wire data is the character-strings in order; `from_wire` concatenates
them and `to_wire` emits 255-octet chunks. Pseudo-types have no wire form.

The inspector converts answers through the same typed constructors (section 8.5), so there is one
definition of each canonical form.

### 4.9 Non-canonical data

A client reads provider text with a private constructor that first tries the strict parser (with the
provider's TXT dialect and name convention). If that fails, the value is kept as the provider's
text, trimmed of surrounding whitespace, and marked non-canonical. A client may also keep text the
strict parser accepts as non-canonical where the provider's reading of it is not established (a name
without the trailing dot inside a value, text with a backslash); such a value stays non-canonical
through a storage round trip.

- `is_canonical()` is false; `to_wire` and the typed `from_data` fail with `NotCanonical`.
- It still compares by text, so an application sees it as a distinct value and a listing never fails
  because of one odd record.
- A write accepts a non-canonical member only when the rrset currently at the provider, as read at
  the start of the write, contains a record with exactly that text; the record is then left as it
  is. Otherwise the write is `InvalidInput`. In practice an application can write back a set it
  listed, with members added or removed, also after storing it (section 2.2); it cannot introduce a
  record through non-canonical data. This is the validation that section 3.1 says happens after the
  read.
