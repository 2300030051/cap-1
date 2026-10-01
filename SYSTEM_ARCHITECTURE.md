# System Architecture

```text
Issuer
  |
  v
Express Session Authentication
  |
  v
Credential Issue / Revoke Routes
  |                       |
  |                       +----> Local AcademicCredentialProof contract
  |                              (hash, issuer address, timestamp, revoked flag)
  |
  +----> SQLite credential + blockchain metadata
  |
  +----> Local issuer/student DID identities
  |        |
  |        +----> Ed25519-signed Verifiable Credential
  |                    |
  |                    v
  |               Student wallet APIs / VC export
  |
  +----> QR contains public verification URL with credential ID
                              |
                              v
                       Public verifier
                   hash + VC + chain + status

Issuer-authenticated document upload
  |
  v
Private temporary staging (10 MB max, random filename)
  |
  v
Local document analysis (Poppler for PDF; byte parsers for PNG/JPEG)
  |                  |
  |                  +----> SHA-256, metadata, structure, text, field matches
  |                  +----> Deterministic explainable risk score
  |
  +----> Existing VC signature/binding checks (reported separately)
  +----> Existing blockchain proof/status checks (reported separately)
  |
  +----> SQLite analysis history (JSON only; upload deleted)
```

The AI/document score is a local heuristic risk indicator. It cannot override credential status, VC cryptography, or blockchain state. SQLite remains the application record; the contract stores only minimal proof data and does not store student attributes or uploaded documents.
