# SecureMailScope — Data Handling Policy

## Core Rules

1. **Do not commit real packet captures.** Never commit `.pcap`, `.pcapng`, `.cap`, or compressed variants to this repository.
2. **Use only public, synthetic, or explicitly authorised sanitised data.** Synthetic data must be documented with its generation method.
3. **Keep raw PCAPs local.** Store all working captures in `runtime/uploads/` (excluded from Git).
4. **Maintain source and origin notes.** For any PCAP used in testing, document: source, acquisition date, authorisation basis, and SHA-256 hash.
5. **Do not use private keys, credentials, or decrypted email content.** Even in synthetic data.
6. **Do not include personal data, email addresses of real individuals, or private IP address ranges** belonging to real organisations.

## .gitignore Protection

The `.gitignore` file protects the following sensitive file types:

- `*.pcap`, `*.pcapng`, `*.cap`, `*.pcap.gz`
- `*.key`, `*.pem`, `*.crt`, `*.p12`, `*.pfx`
- `*.log`, `*.sqlite`, `*.db`
- `runtime/*` (all runtime data)
- `data/raw/*`, `data/processed/*`
- `samples/*` (except README and .gitkeep)
- `models/*` (except README and .gitkeep)

## Data Storage Locations

| Location | Purpose | Git Status |
|----------|---------|------------|
| `runtime/uploads/` | Incoming PCAP files | Excluded |
| `runtime/zeek_logs/` | Zeek output logs | Excluded |
| `runtime/reports/` | Generated reports | Excluded |
| `data/raw/` | Reference raw data | Excluded |
| `data/processed/` | Processed/canonical data | Excluded |
| `data/synthetic/` | Synthetic test data (no real PII) | Case-by-case |

## Future Phases

Each phase that introduces new data handling must update this document and the relevant `.gitignore` entries before the phase is accepted as complete.
