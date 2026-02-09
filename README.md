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

### Intermediate Representation (IR)

Every format module parses into and renders from this JSON structure:

```json
{
  "meta": {
    "source_format": "combolist_user_pass",
    "source_name": "dump.txt",
    "record_count": 3,
    "columns": ["email", "password"],
    "field_confidence": {
      "email": 0.95,
      "username": 0.60,
      "password": 1.0
    }
  },
  "records": [
    {
      "identifier": "user_or_email",
      "email": "user@example.com",
      "username": "someuser",
      "password": "plaintext_or_null",
      "hash": "$2b$10$...",
      "salt": "abcdef",
      "url": "https://example.com",
      "ip": "192.168.1.1",
      "extra": {
        "phone": "555-0100",
        "created_at": "2024-01-15",
        "totp_secret": "JBSWY3DPEHPK3PXP"
      }
    }
  ]
}
```

**Field notes:**
- `columns` — tracks which fields actually have data. A combolist only has `email` + `password`; an SQL dump might have all fields.
- `field_confidence` — per-field accuracy map (0.0–1.0) indicating how confident the parser is that it correctly detected and mapped each field. For example, a combolist parser can't always distinguish `email` vs `username` without validation, so it might report `{"email": 0.9, "username": 0.6}`. A CSV with explicit headers would report `1.0` for all mapped fields.
- `extra` — freeform map for format-specific fields that don't map to universal fields (e.g., TOTP secrets, phone numbers, creation dates). New fields can be added per-format via `extra` without changing the IR schema.
- `identifier` — a fallback when the parser can't determine if a value is an email or username.

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
