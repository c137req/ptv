# ptv
a universal data parsing daemon, binary, and RESTful API

```
source.Parse(raw) → IR → target.Render(ir)
```

any format can convert to any other format. add a new module and it automatically works with all existing ones.

## install

requires go 1.22 or later.

```bash
go install github.com/c137req/ptv@latest
```

or build from source:

```bash
git clone git@github.com:c137req/ptv.git
cd ptv
go build .
```

## usage

### cli

```bash
# convert csv to json
ptv -from csv -to json_flat -i data.csv -o output.json

# pipe through stdin/stdout
cat data.csv | ptv -from csv -to json_flat > output.json

# convert with verbose logging
ptv -from shadow -to csv -i /etc/shadow -o - -v

# list all available formats
ptv -formats
```

### api server

ptv includes a built-in http api server with daemon management. see the [api documentation](WIKI.md) for full details.

```bash
# start the api server
ptv -daemon start -v

# stop the server
ptv -daemon stop

# check if running
ptv -daemon status
```

quick conversion via the api:

```bash
DATA=$(base64 -w0 < input.csv)
curl -X POST \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$DATA\"}" \
  http://localhost:0474/convert/csv/json_flat \
  | jq -r '.data' | base64 -d
```

## supported formats

83 formats across 14 categories.

### credentials & text
| format | description |
|--------|-------------|
| `plaintext` | single field per line |
| `combolist_user_pass` | `user:pass` pairs |
| `combolist_email_pass` | `email:pass` pairs |
| `combolist_user_pass_url` | `user:pass:url` triples |
| `combolist_extended` | variable-field combos |
| `stealer_logs` | browser credential dumps (redline/racoon) |
| `shadow` | unix `/etc/shadow` |
| `passwd` | unix `/etc/passwd` |
| `htpasswd` | apache `user:hash` |
| `base64_creds` | base64 `user:pass` (http basic auth) |

### hashes & cracking
| format | description |
|--------|-------------|
| `hashlist_plain` | one hash per line |
| `hashlist_user_hash` | `user:hash` pairs |
| `hashlist_hash_salt` | `hash:salt` pairs |
| `modular_crypt` | `$algo$params$salt$hash` |
| `jtr_pot` | john the ripper cracked results |
| `hashcat_pot` | hashcat cracked results |
| `rainbow_table` | pre-computed hash chains |

### tabular & structured
| format | description |
|--------|-------------|
| `csv` | comma-separated values |
| `tsv` | tab-separated values |
| `json_flat` | flat json array of objects |
| `json_nested` | nested/app-specific json |
| `xml_generic` | arbitrary xml |
| `yaml` | yaml documents |
| `excel` | xlsx spreadsheets |

### sql dumps
| format | description |
|--------|-------------|
| `sql_dump_mysql` | mysql dialect |
| `sql_dump_postgres` | postgresql dialect |
| `sql_dump_mssql` | mssql/t-sql dialect |
| `sql_dump_oracle` | oracle/pl-sql dialect |
| `sqlite` | sqlite databases |

### nosql & modern databases
| format | description |
|--------|-------------|
| `bson` | mongodb binary json |
| `redis_rdb` | redis binary snapshot |
| `redis_aof` | redis append-only log |
| `neo4j_cypher` | cypher create/merge statements |
| `dynamodb_json` | aws dynamodb typed export |
| `influxdb_lp` | influxdb line protocol |
| `firebase_json` | firebase realtime db export |
| `firestore_json` | firestore document export |
| `couchdb_json` | couchdb document export |
| `cassandra_cql` | cassandra cql copy format |

### password managers
| format | description |
|--------|-------------|
| `keepass_xml` | keepass 2.x xml export |
| `lastpass_csv` | lastpass csv export |
| `onepassword_csv` | 1password csv export |
| `bitwarden_json` | bitwarden json export |
| `bitwarden_csv` | bitwarden csv export |
| `chrome_csv` | chrome password export |

### browsers & cookies
| format | description |
|--------|-------------|
| `firefox_json` | firefox json export |
| `netscape_cookie` | netscape cookie format |
| `safari_csv` | safari csv export |
| `browser_sqlite` | chrome/firefox sqlite dbs |

### directory & identity
| format | description |
|--------|-------------|
| `ldif` | ldap data interchange format |
| `vcard` | vcard contact format |

### configuration files
| format | description |
|--------|-------------|
| `toml` | toml config |
| `ini` | ini/properties/conf |
| `hcl` | hashicorp config language |
| `plist` | macos property list |
| `env` | `.env` key=value files |

### serialisation & binary
| format | description |
|--------|-------------|
| `msgpack` | messagepack binary |
| `cbor` | concise binary object representation |
| `protobuf` | protocol buffers (schema-less) |
| `avro` | apache avro |
| `parquet` | apache parquet |
| `thrift` | apache thrift binary |
| `bencode` | bittorrent encoding |

### auth & cryptography
| format | description |
|--------|-------------|
| `jwt` | json web tokens |
| `x509_pem` | pem-encoded certificates |
| `x509_der` | der-encoded certificates |
| `pkcs12` | pkcs#12 containers |
| `ssh_authorized_keys` | ssh public keys |
| `ssh_private_key` | ssh private keys |
| `kerberos_keytab` | kerberos keytab files |
| `gpg_keyring` | gpg/pgp keyrings |
| `ethereum_keystore` | ethereum wallet json |

### logs
| format | description |
|--------|-------------|
| `syslog` | rfc 5424 syslog |
| `access_log` | apache/nginx access logs |
| `evtx` | windows event logs |
| `journald` | systemd journal |

### network & vpn
| format | description |
|--------|-------------|
| `openvpn` | openvpn client config |
| `wireguard` | wireguard config |
| `windows_wifi_xml` | windows wifi profiles |

### applications
| format | description |
|--------|-------------|
| `telegram_json` | telegram chat export |
| `discord_json` | discord data package |
| `docker_config` | docker registry auth |
| `aws_credentials` | aws credentials/config |

## intermediate representation

every record passes through a common IR with typed fields:

- **identity**: email, username, phone, name
- **credentials**: password, hash (type + value), salt (value + encoding)
- **network**: url, domain, ip, port
- **unknowns**: values the parser couldn't definitively classify, stored with confidence scores
- **extra**: format-specific fields that don't fit the universal schema

data is never discarded — anything that can't be mapped to a known field goes into unknowns with the parser's best guess at what it might be.

## licence

MIT
