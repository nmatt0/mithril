# User-defined rules

mithril ships built-in rules for secrets, credential files, and SBOM sources. You can add your own with
`--rules <file.json>` — for target-specific credentials, vendor patterns, or "flag every file that
looks like X". User rules feed the same engine as the built-ins (see `docs/engine-design.md`); they get the
safe declarative subset, not the code-level validators (CRC32/JWT/PEM stay built in).

```
mithril --secrets --rules myrules.json ./rootfs/
```

A load error (unreadable file, bad JSON, invalid regex, a rule missing required fields) is **fatal** — a
typo should not silently scan with fewer rules than you think.

## File format

A JSON object with two optional arrays:

```json
{
  "path_rules": [
    {"glob": "**/*.p12", "category": "crypto", "type": "pkcs12", "description": "PKCS12 keystore."}
  ],
  "content_rules": [
    {"type": "vendor-cred", "category": "secret", "anchors": ["ADMIN_PW"],
     "regex": "ADMIN_PW\\s*=\\s*(\\S+)", "description": "Vendor admin password."},
    {"type": "internal-host", "category": "config", "anchors": ["update.corp.local"],
     "description": "Reference to the internal update host."}
  ]
}
```

### `path_rules` — flag files by name

Matched against each file's path relative to the scan root.

| field | required | meaning |
|---|---|---|
| `glob` | yes | `*` matches within a path segment, `**` across segments, `?` a single char. Anchored at both ends. |
| `category` | no (default `config`) | grouping tag: `crypto` / `credential-file` / `config` / … |
| `type` | no (default `user-notable`) | the finding type shown in output |
| `description` | no | one-line human description |

A match becomes a **notable-file** finding.

### `content_rules` — match inside file content

| field | required | meaning |
|---|---|---|
| `anchors` | yes | one or more literal strings; any occurrence selects the rule (fast multi-pattern prefilter) |
| `regex` | no | ECMAScript regex run on a bounded window **anchored at the anchor**; capture group 1 (if present) becomes the finding's label |
| `type` | no (default `user-content`) | the finding type |
| `category` | no (default `config`) | `secret` / `config` / … |
| `min_entropy` | no (default 0) | drop matches whose token entropy (bits/byte) is below this — useful to cut noise on high-value patterns |
| `description` | no | one-line human description |

- **With a `regex`:** the match extends to the regex match; group 1 is extracted as the value/label. The
  regex only ever runs on the short window an anchor produces, so it cannot cause runaway backtracking.
- **Without a `regex`:** a plain keyword-presence match — the anchor itself is the finding.

User content findings sit at the `pattern` confidence tier (the `structural`/`validated` tiers require the
built-in code validators).

A worked example lives in `examples/rules.example.json`.
