"""
SecureMailScope — ML sub-package.

Phase 0: placeholder only. A separate local IsolationForest anomaly-
ranking model will be implemented in Phase 7.

The ML model:
  - Uses Zeek-derived session features only (not raw PCAP payloads).
  - Outputs anomaly scores and review recommendations.
  - Does NOT override deterministic rule-engine findings.
  - Does NOT confirm attacks, exploits, or attribution.
"""
