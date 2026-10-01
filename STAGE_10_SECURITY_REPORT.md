# Stage 10 Security Report

## 1. Scope
This was a security and reliability audit of the integrated Stages 1–9. No major feature, UI redesign, smart-contract change, external service, or major dependency migration was introduced. The existing local SQLite, Express sessions, Hardhat/ethers, DID/VC, student wallet, QR, and deterministic local document-analysis architecture remains in use.

## 2. Security checks performed
- Reviewed authentication, login/logout, session regeneration, issuer authorization, cookie attributes, public routes, and API response contents.
- Reviewed POST/PATCH request parsing, credential field types and lengths, wallet identifiers, multipart limits/type checks, generated upload names, filesystem handling, and failure responses.
- Audited SQL query construction, SQLite integrity, relationship orphans, schema constraints, and indexes.
- Exercised issue and revoke success/failure against the live local chain and an isolated unavailable-RPC test server.
- Reviewed DID key generation/persistence, VC signing/verification and identity binding, public verification, QR origin construction, document analysis, error output, and secret exposure.
- Searched application/frontend files for `innerHTML`, obvious hardcoded private keys, and unsafe user-controlled SQL interpolation. No `innerHTML` use or interpolated user SQL was found.
- Verified the example environment no longer embeds the known Hardhat test private key. The actual `.env` was not modified.

## 3. Issues discovered
- Invalid JSON used Express's default parser error response instead of the application's controlled JSON error shape; oversized JSON had no explicit body cap.
- Public wallet endpoints could provision arbitrary DID identities and persist private keys from attacker-selected identifiers.
- A newly generated student DID key was persisted before blockchain anchoring, leaving an orphan local private identity on anchor failure even though SQLite stayed clean.
- Login string inputs had no byte-length bounds.
- Blockchain verification errors returned raw provider error strings to the public verifier.
- QR origin construction manually trusted forwarded host/protocol headers regardless of Express proxy-trust configuration.
- `.env` and SQLite DB files were not ignored by Git rules; `.env.example` contained the publicly known Hardhat test-account key.
- The existing `.gitignore` was UTF-16LE, making its rules unsuitable for reliable Git ignore parsing.
- SQLite has no declared foreign-key constraints on credential/VC/identity/analysis relationships. The current database audit found no orphans; no destructive rebuild was attempted.

## 4. Issues fixed
- Added a 64 KB JSON request-body cap and sanitized 400/413/500 JSON error handling for malformed or oversized requests.
- Bounded login username/password byte lengths before bcrypt work.
- Changed public wallet creation/lookup endpoints to resolve existing issuer-created wallets only; arbitrary requests no longer generate or persist a DID/key.
- Split ephemeral DID generation from key-store persistence. New student private keys are persisted only after the blockchain anchor succeeds; identity, credential, blockchain metadata, and VC are then committed in one SQLite transaction.
- Sanitized public blockchain failure messages.
- QR URLs now use configured `PUBLIC_ORIGIN` or Express's proxy-aware request origin, instead of directly trusting forwarded headers.
- Added `.env`, `credentials.db`, and SQLite sidecar ignores; replaced the example Hardhat private key with a placeholder.
- Converted `.gitignore` to plain UTF-8 without a BOM so all ignore patterns, including `node_modules/`, are parseable.
- Extended security regression tests for malformed JSON, oversized login input, read-only wallet lookup, failed anchoring without SQLite/key-store orphans, failed revocation without SQLite state changes, SQL-injection-shaped input, malformed documents, logout invalidation, cookie attributes, and QR forwarded-header spoofing.

## 5. Tests performed
- `npm test`: passed. 5 Hardhat/VC tests passed; 4 Stage 8 Node/HTTP integration tests passed.
- Backend syntax checks passed for `server.js`, `blockchainService.js`, `didService.js`, `verifiableCredentialService.js`, `aiAuthenticityService.js`, `database.js`, and relevant test files.
- VS Code diagnostics reported no errors in checked files.
- The unavailable-RPC issue test returned a controlled 502 and left zero credential, VC, and student identity rows in its isolated database; the identity key store was unchanged.
- The unavailable-RPC revoke test returned a controlled 502, preserved SQLite status and transaction metadata, and public verification did not report a false `REVOKED` result.
- SQLite `integrity_check` returned `ok`; current database audit found zero orphan VC records, credential-linked analysis records, or VC-to-wallet links. Existing legacy `REVOKED`/`NOT_ANCHORED` rows were retained unchanged. There are no declared foreign-key constraints.
- The HTTP regression test confirmed `HttpOnly` and `SameSite=Lax`. The conditional `Secure` flag for `NODE_ENV=production` was verified by configuration review, not by a production deployment test.
- `git diff --check` could not be run because the workspace directory is not a Git repository. Consequently, whether `.env` is tracked cannot be verified here; it is now covered by `.gitignore`.

## 6. End-to-end validation
A new credential was issued using the existing registered student wallet and the healthy local Hardhat node (chain ID 1337). Its SQL-injection-shaped degree was stored literally, with no SQL effect.

- Credential ID: `57c3f83e-a041-437f-971c-fec99480e1f5`
- Anchor transaction: `0xe1cbf3276f9ffacef86044911bb68cb02f2fdaeb196806d1fd554b6ba5c6ec4d`
- Revoke transaction: `0x9d5cee6a468725422552451953b62adba8a50c2cba8caf69b6d0a9b413259db4`
- VC signature and issuer/student binding passed; wallet retrieval and VC export passed.
- Public verification returned `VALID` before revoke and `REVOKED` afterward. The wallet and chain also reflected `REVOKED`.
- QR PNG generation and public verification page loading passed before and after revoke. A spoofed forwarded host/protocol did not change QR bytes when `PUBLIC_ORIGIN` was configured. The QR payload was not decoded because no local decoder is installed.
- Matching PDF analysis scored 95 deterministically with all expected fields matching. A modified degree produced a different hash, a field mismatch, and a lower score.
- Temporarily altered SQLite credential data was reported `INVALID` by hash verification; restoring it returned verification to `VALID`.
- Post-revocation AI analysis retained the document score while reporting blockchain and credential status as `REVOKED`.
- Private-file URLs returned 404, response checks found no session/blockchain secret or private-key fields, uploaded temporary files were removed, and logout invalidated the issuer session.
- Temporary application servers and isolated test databases were stopped/removed. The pre-existing app on port 3000 and Hardhat node were not stopped. The new on-chain credential remains revoked in SQLite/chain as a coherent demo record.

## 7. Remaining known limitations
- This remains a local academic demo, not production-ready identity, wallet, document forensics, or security infrastructure.
- Student wallet ownership is not authenticated; wallet APIs expose the demo credential presentation to anyone who knows the wallet identifier.
- DID private keys are plaintext at rest in the local, owner-restricted identity JSON file. The application relies on host filesystem permissions.
- A blockchain transaction cannot be rolled back if post-mining local persistence fails. The app validates before submission and uses a SQLite transaction afterward; rare disk/database failure after chain success still needs manual reconciliation.
- Existing database relationships have no foreign-key constraints. Current rows were clean; adding constraints would require a migration and was intentionally not attempted.
- Legacy records may be revoked without a blockchain record, or valid without Stage 6 anchoring; these predate the complete integration and were preserved.
- Image OCR and sophisticated forensic analysis are not implemented. PDF/image heuristics, metadata, and the score are not proof of authenticity.
- QR PNGs were generated and their URL route was tested, but a bitmap decoder was unavailable for independent payload decoding.
- `Secure` cookies are enabled only when `NODE_ENV=production`; deployments behind a proxy must configure trust-proxy settings and `PUBLIC_ORIGIN` correctly.

## 8. Dependency audit findings
`npm audit --omit=dev` reports 19 advisories: 11 low, 3 moderate, and 5 high. Affected transitive packages reported include `adm-zip`, `cookie`, `diff`, `elliptic`, `qs`, `serialize-javascript`, `tmp`, `undici`, and `uuid`, primarily through the existing Hardhat 2/solc tree. Hardhat is currently listed under application dependencies, so npm includes this tree in the production audit; the Express request path does not import Hardhat, but the packages remain installed in the deployment dependency set. npm recommends a breaking Hardhat 3 upgrade for a clean audit. No dependency upgrade was applied in this security-only stage.

## 9. Production hardening recommendations
- Move issuer and wallet access behind a production identity provider or authenticated authorization model; do not treat wallet IDs as proof of ownership.
- Use a managed secret/key store or encrypted/HSM-backed DID signing keys; rotate any development keys before real deployment.
- Plan a reviewed, backup-tested SQLite migration to add foreign keys and reconciliation tooling for transactions mined before a local persistence failure.
- Set strong secrets, HTTPS, `NODE_ENV=production`, trusted proxy hops, and a fixed `PUBLIC_ORIGIN`; restrict CORS to known origins if cross-origin clients are needed.
- Review and schedule the transitive Hardhat/solc advisory remediation separately, with compatibility and contract-test coverage rather than a blind major upgrade.
- Run local document parsers with OS-level isolation/resource limits and retain human review for authenticity decisions.
