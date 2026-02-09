# ptv
Parse The Veil is an all-around data parsing RESTful API. i love ptv

## Plan

### Architecture

Hub-and-spoke model — every format module converts TO and FROM a common **Intermediate Representation (IR)**. Any-to-any conversion works like this:

```
Source.Parse(raw) → IR → Target.Render(ir)
```

- Go is the primary API server
- Python modules are called via subprocess (JSON over stdin/stdout) only when Python has significantly better library support
- Each module exposes exactly two operations: **Parse** (from that format → IR) and **Render** (IR → that format)

```
┌─────────────┐     ┌─────────┐     ┌──────────────┐
│ Input (any   │────▶│  Module  │────▶│     IR       │
│ of 85 fmts)  │     │ .Parse() │     │ (common JSON)│
└─────────────┘     └─────────┘     └──────┬───────┘
                                           │
                                           ▼
                                    ┌─────────┐     ┌──────────────┐
                                    │  Module  │────▶│ Output (any  │
                                    │ .Render()│     │ of 85 fmts)  │
                                    └─────────┘     └──────────────┘

Go API Server
├── Go modules    → direct function calls (fast)
└── Python modules → subprocess, JSON over stdin/stdout
```

### PTV Universal Format

The PTV universal format is the project's native representation. Every record is explicitly typed — no field is ambiguous. Every record gets a unique `ptv_<uuid4>` identifier. **Data is never discarded** — values that can't be definitively mapped to a known field are stored as unknowns with potential field guesses. The format is defined in Go at `internal/ir/record.go`.

```json
{
  "ptv_version": "1.0",
  "meta": {
    "source_format": "combolist_user_pass",
    "source_file": "dump.txt",
    "parsed_at": "2026-02-09T12:00:00Z",
    "record_count": 2,
    "columns": ["email", "password"],
    "field_confidence": {
      "email": 0.95,
      "username": 0.60,
      "password": 1.0
    }
  },
  "records": [
    {
      "ptv_id": "ptv_550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "username": "someuser",
      "phone": "+15555550100",
      "name": "John Doe",
      "password": "plaintext_if_known",
      "hash": {
        "type": "bcrypt",
        "value": "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
      },
      "salt": {
        "value": "abcdef1234567890",
        "encoding": "hex"
      },
      "url": "https://example.com/login",
      "domain": "example.com",
      "ip": "192.168.1.1",
      "port": 443,
      "unknowns": [
        {
          "value": "jdoe_backup",
          "potential_fields": [
            {"field": "username", "confidence": 0.7},
            {"field": "name", "confidence": 0.2}
          ]
        },
        {
          "value": "x8k2mNq",
          "potential_fields": [
            {"field": "password", "confidence": 0.5},
            {"field": "hash", "confidence": 0.3}
          ]
        },
        {
          "value": "something_completely_unknown",
          "potential_fields": []
        }
      ],
      "extra": {
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "created_at": "2024-01-15"
      }
    }
  ]
}
```

#### Field rules

**`ptv_id`** — every record gets `ptv_<uuid4>`. Generated on parse, persists through conversions. This is the universal record identifier across all PTV operations.

**Identity fields:**
| Field | Format | Rule |
|-------|--------|------|
| `email` | RFC 5322 | Must contain `@`. Only set when the parser is confident the value is an email. |
| `username` | string | No `@` allowed. If the source is ambiguous (could be email or username), parsers should use `email` if it contains `@`, `username` otherwise. |
| `phone` | `+<digits>` | **No spaces, dashes, parentheses, or symbols except the leading `+`.** Raw input like `(555) 555-0100` gets normalized to `+15555550100`. |
| `name` | string | Display name / full name if available. |

**Credential fields:**
| Field | Format | Rule |
|-------|--------|------|
| `password` | string | Plaintext password, if known. |
| `hash` | `{"type": "<algo>", "value": "<string>"}` | Hash value with its identified algorithm type. See hash types below. |
| `salt` | `{"value": "<string>", "encoding": "<hex\|base64\|utf8\|raw>"}` | Salt with its encoding explicitly declared. |

**Hash types** (auto-detected by `DetectHashType()`):

| Type | Identified by |
|------|---------------|
| `bcrypt` | `$2a$`, `$2b$`, `$2y$` prefix |
| `argon2id` | `$argon2id$` prefix |
| `argon2i` | `$argon2i$` prefix |
| `scrypt` | `$scrypt$` prefix |
| `pbkdf2` | `$pbkdf2` prefix |
| `sha512crypt` | `$6$` prefix |
| `sha256crypt` | `$5$` prefix |
| `md5crypt` | `$1$` prefix |
| `apr1` | `$apr1$` prefix |
| `sha1crypt` | `$sha1$` prefix |
| `mysql` | `*` + 40 hex chars |
| `md5` | 32 hex chars |
| `sha1` | 40 hex chars |
| `sha224` | 56 hex chars |
| `sha256` | 64 hex chars |
| `sha384` | 96 hex chars |
| `sha512` | 128 hex chars |
| `ntlm` | 32 hex chars (context-dependent, same length as MD5) |
| `unknown` | Anything that doesn't match the above patterns |

**Network fields:**
| Field | Format | Rule |
|-------|--------|------|
| `url` | string | Full URL if available. |
| `domain` | string | Domain extracted from URL, or standalone. |
| `ip` | string | IPv4 or IPv6, no port. |
| `port` | integer | Numeric, 1–65535. Zero means not set. |

**`unknowns`** — **data is never discarded.** When a parser encounters a value it cannot definitively map to a known field, it goes here as an `UnknownField`:

| Field | Format | Rule |
|-------|--------|------|
| `value` | string | The raw value exactly as parsed. Never modified or normalized. |
| `potential_fields` | `[{"field": "<name>", "confidence": 0.0–1.0}, ...]` | Parser's best guesses for what known field this value belongs to. Empty array if the parser has no guess. |

The rule is simple: **confirmed values go into their named field, unconfirmed values go into `unknowns`.** A combolist line like `jdoe:x8k2mNq` where the parser can confirm `jdoe` looks like a username (no `@`, reasonable format) puts it in `username` — but if `x8k2mNq` could be a password or a short token and the parser can't tell, it goes into `unknowns` with `[{"field": "password", "confidence": 0.5}, {"field": "hash", "confidence": 0.3}]`. Values with zero guesses (completely unidentifiable) still get stored with an empty `potential_fields` array.

**`extra`** — freeform `map[string]any` for format-specific fields that don't map above (TOTP secrets, creation dates, group names, notes, etc.). This is how the format extends without schema changes. Unlike `unknowns`, `extra` is for values where the parser *knows* what the field is — it just isn't one of the universal fields.

**Meta fields:**
| Field | Purpose |
|-------|---------|
| `source_format` | Module name that produced this dataset. |
| `source_file` | Original filename, if known. |
| `parsed_at` | ISO 8601 timestamp of when parsing occurred. |
| `record_count` | Number of records in the dataset. |
| `columns` | Which Record fields actually have data (e.g., a combolist only populates `email` + `password`). |
| `field_confidence` | Per-field map of 0.0–1.0 indicating parser confidence. A CSV with explicit headers reports `1.0` for all mapped fields. A combolist parser that can't distinguish email vs username might report `{"email": 0.9, "username": 0.6}`. |

### Easibility Scores

Each format has a **FROM** score (parsing from that format into IR) and a **TO** score (rendering IR into that format), rated out of 10:

| Range | Meaning |
|-------|---------|
| **9–10** | Trivial — stdlib or single-function calls, near-zero ambiguity |
| **7–8** | Straightforward — good library support, minor edge cases |
| **5–6** | Moderate — needs dialect handling, schema knowledge, or limited libraries |
| **3–4** | Difficult — complex/binary formats, sparse library support |
| **1–2** | Very hard — proprietary/undocumented, or requires external tooling |

### Format Modules (85 total)

#### Credential & Text Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 1 | Plain Text (one-per-line) | Single field per line (passwords, emails, etc.) | Go | stdlib | 9 | 10 |
| 2 | Combolist (user:pass) | Colon-delimited two-field credential pairs | Go | stdlib | 9 | 10 |
| 3 | Combolist (email:pass) | Email-specific variant of #2 | Go | stdlib | 9 | 10 |
| 4 | Combolist (user:pass:url) | Three-field extended combo with URL | Go | stdlib | 8 | 9 |
| 5 | Combolist (user:pass:url:extra) | Variable-field extended combo | Go | stdlib | 7 | 8 |
| 6 | Stealer Logs | Directory-structured browser credential dumps (Autofills, Cookies, Passwords) | Python | `stealer-parser`, existing parser | 4 | 3 |
| 7 | /etc/shadow | Unix shadow password file (`user:$algo$salt$hash:...`) | Go | stdlib | 8 | 7 |
| 8 | /etc/passwd | Unix password file (colon-delimited, 7 fields) | Go | stdlib | 9 | 8 |
| 9 | htpasswd | Apache `username:hash` with bcrypt/MD5/SHA1 variants | Go | `tg123/go-htpasswd` | 8 | 8 |
| 10 | Base64 Encoded Credentials | Base64-wrapped `user:pass` (HTTP Basic Auth style) | Go | `encoding/base64` | 10 | 10 |

#### Hash & Cracking Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 11 | Hash List (hash-only) | One hash per line, any algorithm | Go | stdlib | 8 | 9 |
| 12 | Hash List (user:hash) | Username paired with hash | Go | stdlib | 8 | 9 |
| 13 | Hash List (hash:salt) | Hash with explicit salt field | Go | stdlib | 7 | 8 |
| 14 | Modular Crypt Format | `$algo$params$salt$hash` (bcrypt, scrypt, argon2, etc.) | Python | `passlib` | 6 | 7 |
| 15 | John the Ripper POT | Cracked results: `hash:plaintext` | Go | stdlib | 9 | 9 |
| 16 | Hashcat POT / Output | Cracked results with optional mode prefix | Go | stdlib | 8 | 8 |
| 17 | Rainbow Tables (Ophcrack/RainbowCrack) | Pre-computed hash chain tables (.rt, .tbl) | Python | custom | 4 | 3 |

#### Tabular & Structured Data

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 18 | CSV | Comma-separated values with header row | Go | `encoding/csv` | 10 | 10 |
| 19 | TSV | Tab-separated values | Go | `encoding/csv` (tab delimiter) | 10 | 10 |
| 20 | JSON (flat records) | Array of uniform objects | Go | `encoding/json` | 10 | 10 |
| 21 | JSON (nested/app-specific) | Schema-specific JSON (needs field mapping) | Go | `encoding/json` | 7 | 7 |
| 22 | XML (generic) | Arbitrary XML with credential-like elements | Go | `encoding/xml` | 7 | 7 |
| 23 | YAML | YAML documents/lists | Go | `gopkg.in/yaml.v3` | 9 | 9 |
| 24 | Excel (XLSX) | Spreadsheet with header row | Python | `openpyxl` | 6 | 6 |

#### SQL & Relational Database Dumps

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 25 | SQL Dump — MySQL | DDL + INSERT statements, MySQL dialect | Python | `sqlparse` | 5 | 6 |
| 26 | SQL Dump — PostgreSQL | DDL + COPY/INSERT, PostgreSQL dialect | Python | `sqlparse` | 4 | 5 |
| 27 | SQL Dump — SQLite | Simpler SQL dialect, single-file DB | Go | `database/sql`, `modernc.org/sqlite` | 7 | 7 |
| 28 | SQL Dump — MSSQL | T-SQL dialect, complex syntax | Python | `sqlparse` | 4 | 4 |
| 29 | SQL Dump — Oracle | PL/SQL dialect | Python | `sqlparse` | 3 | 4 |

#### NoSQL & Modern Database Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 30 | BSON (MongoDB binary) | MongoDB's binary JSON serialization | Go | `go.mongodb.org/mongo-driver/bson` | 7 | 7 |
| 31 | MongoDB mongodump | Directory of .bson files with metadata | Go | `go.mongodb.org/mongo-driver` | 6 | 6 |
| 32 | Redis RDB | Binary point-in-time snapshot | Python | `redis-rdb-tools` | 5 | 5 |
| 33 | Redis AOF | Append-only text log of write ops | Go | stdlib (Redis protocol parsing) | 8 | 8 |
| 34 | Neo4j Cypher Script | CREATE/MERGE statements for graph data | Python | `neo4j` driver | 5 | 6 |
| 35 | DynamoDB JSON | AWS DynamoDB export with typed values | Go | `aws-sdk-go-v2` | 7 | 7 |
| 36 | InfluxDB Line Protocol | `measurement,tags fields timestamp` | Go | stdlib (text parsing) | 8 | 8 |
| 37 | Firebase Realtime DB JSON | Nested JSON tree export | Go | `encoding/json` | 9 | 9 |
| 38 | Firestore JSON/JSONL | Flat or nested document exports | Go | `encoding/json` | 9 | 8 |
| 39 | CouchDB/Couchbase JSON | JSON document exports | Go | `encoding/json` | 9 | 9 |
| 40 | Cassandra CQL COPY | CSV-like CQL export format | Go | `encoding/csv` | 8 | 8 |

#### Password Manager Exports

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 41 | KeePass XML Export | KeePass 2.x XML export format | Python | `pass-import` | 7 | 5 |
| 42 | LastPass CSV Export | CSV with `url,username,password,totp,extra,name,grouping,fav` | Go | `encoding/csv` | 9 | 9 |
| 43 | 1Password CSV Export | CSV with 1Password-specific headers | Go | `encoding/csv` | 9 | 8 |
| 44 | Bitwarden JSON Export | JSON with folders, items, login objects | Go | `encoding/json` | 8 | 7 |
| 45 | Bitwarden CSV Export | Flattened CSV variant | Go | `encoding/csv` | 9 | 9 |
| 46 | Chrome CSV Export | `name,url,username,password` | Go | `encoding/csv` | 9 | 9 |

#### Browser & Cookie Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 47 | Firefox JSON Export | JSON with Mozilla-specific fields (httpRealm, formActionOrigin, etc.) | Go | `encoding/json` | 8 | 7 |
| 48 | Netscape Cookie Format | Tab-separated cookie file (curl/wget/browser compatible) | Go | `aki237/nscjar` | 7 | 7 |
| 49 | Safari CSV Export | Apple's CSV credential export | Go | `encoding/csv` | 9 | 9 |
| 50 | Browser SQLite DB | Chrome/Firefox credential SQLite databases | Go | `modernc.org/sqlite` | 7 | 6 |

#### Directory & Identity Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 51 | LDIF (LDAP) | LDAP Data Interchange Format (RFC 2849) | Python | `python-ldap`, `ldif` | 5 | 5 |
| 52 | vCard (VCF) | Contact card format with potential credential metadata | Go | `emersion/go-vcard` | 7 | 7 |

#### Configuration File Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 53 | TOML | Tom's Obvious Minimal Language | Go | `BurntSushi/toml` | 9 | 9 |
| 54 | INI / .properties / .conf | Key=value config with optional sections | Go | `go-ini/ini` | 9 | 9 |
| 55 | HCL (HashiCorp) | Terraform/Vault config language | Go | `hashicorp/hcl/v2` | 7 | 7 |
| 56 | macOS plist | Apple property list (XML or binary) | Python | `plistlib` (stdlib) | 8 | 8 |
| 57 | .env | `KEY=VALUE` environment variable files | Go | stdlib | 9 | 10 |

#### Serialization & Binary Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 58 | MessagePack | Efficient binary JSON-like serialization | Go | `vmihailenco/msgpack` | 8 | 8 |
| 59 | CBOR | Concise Binary Object Representation (RFC 8949) | Go | `fxamacker/cbor/v2` | 7 | 7 |
| 60 | Protocol Buffers | Schema-driven binary serialization | Go | `google.golang.org/protobuf` | 6 | 6 |
| 61 | Apache Avro | Schema-embedded binary format, data lake standard | Python | `fastavro` | 6 | 7 |
| 62 | Apache Parquet | Columnar storage, big data standard | Python | `pyarrow` | 5 | 5 |
| 63 | Apache Thrift | Facebook RPC serialization | Go | `apache/thrift` | 6 | 6 |
| 64 | FlatBuffers | Google zero-copy serialization | Go | `google/flatbuffers` | 6 | 6 |
| 65 | Bencode (BitTorrent) | BitTorrent metainfo encoding | Go | `anacrolix/torrent` | 7 | 7 |

#### Auth & Cryptographic Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 66 | JWT (JSON Web Token) | `header.payload.signature` (Base64URL) | Go | `golang-jwt/jwt` | 9 | 9 |
| 67 | X.509 Certificate (PEM) | Base64-encoded DER with text headers | Go | `crypto/x509` | 8 | 8 |
| 68 | X.509 Certificate (DER) | Raw binary ASN.1 encoding | Go | `crypto/x509` | 7 | 7 |
| 69 | PKCS#12 (.p12/.pfx) | Binary cert + private key container | Go | `crypto/x509` | 6 | 6 |
| 70 | SSH authorized_keys | One public key per line | Go | `crypto/ssh` | 8 | 8 |
| 71 | SSH Private Key (PEM) | PEM-wrapped private key | Go | `crypto/ssh` | 7 | 7 |
| 72 | Kerberos Keytab | Binary credential file for Kerberos principals | Python | MIT krb5 bindings | 5 | 4 |
| 73 | GPG/PGP Keyring | Exported ASCII-armored or binary keys | Python | `python-gnupg` | 4 | 3 |
| 74 | Ethereum Keystore (UTC/JSON) | Encrypted wallet JSON with Scrypt KDF | Go | `go-ethereum` | 7 | 7 |

#### Log Formats

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 75 | Syslog (RFC 5424) | Standardized system log format | Go | stdlib | 8 | 9 |
| 76 | Apache/Nginx Access Log | Common/Combined log format | Go | stdlib (regex) | 8 | 9 |
| 77 | Windows Event Log (EVTX) | Binary XML event log | Python | `python-evtx` | 6 | 3 |
| 78 | journald (systemd) | Binary journal entries | Python | `systemd` bindings | 6 | 4 |

#### Network & VPN Config

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 79 | OpenVPN (.ovpn) | OpenVPN client config with embedded certs/keys | Go | stdlib (text parsing) | 8 | 9 |
| 80 | WireGuard (.conf) | INI-like peer/interface config | Go | stdlib | 9 | 9 |
| 81 | Windows WiFi Profile (XML) | Windows WLAN XML with optional plaintext keys | Go | `encoding/xml` | 8 | 8 |

#### Application & Platform Exports

| # | Format | Description | Lang | Key Libraries | FROM | TO |
|---|--------|-------------|------|---------------|------|----|
| 82 | Telegram JSON Export | Chat history as JSON | Go | `encoding/json` | 8 | 8 |
| 83 | Discord Data Package | GDPR export with messages as JSON | Go | `encoding/json` | 8 | 8 |
| 84 | Docker config.json | Registry auth with base64 credentials | Go | `encoding/json` | 8 | 8 |
| 85 | AWS credentials / config | INI-style `~/.aws/credentials` | Go | `go-ini/ini` | 9 | 9 |

### Go/Python Split

Go handles the API server and most formats — especially text-based, JSON, CSV, XML, binary serialization, and crypto formats where Go's stdlib and ecosystem are strong.

Python is used only where it has significantly better libraries:
- SQL dump parsing (`sqlparse`)
- Stealer log parsing (`stealer-parser` + existing custom parser)
- Password manager imports (`pass-import`)
- Modular crypt format handling (`passlib`)
- Windows Event Log parsing (`python-evtx`)
- Redis RDB parsing (`redis-rdb-tools`)
- Excel files (`openpyxl`)
- Neo4j Cypher generation (`neo4j` driver)
- LDIF handling (`python-ldap`)
- macOS plist (`plistlib`)
- Rainbow table handling (custom)
- Kerberos/GPG (specialized bindings)

Python modules are standalone scripts. Go calls them via `os/exec`, piping IR JSON over stdin/stdout. Errors go to stderr. Non-zero exit = failure. Stateless and debuggable.
