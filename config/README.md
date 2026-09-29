# Configuration Templates

This folder contains safe example configuration templates only.

- **Offline-First & Local-Only:** SecureMailScope operates entirely offline without external API dependencies or cloud services.
- **Example Templates:** No production or runtime configuration is included in Phase 0. Future phases may load configuration from local TOML files.
- **Safe Usage:** `app.example.toml` and `logging.example.toml` are templates and must be copied and customized locally if needed.
- **Data Protection:** Never store PCAP paths containing sensitive data, credentials, private keys, tokens, or cloud API settings in committed configuration.
- **Status:** No configuration loader is implemented in Phase 0.
