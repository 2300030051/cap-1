# Stage 9 Report: Stages 1-8 Integration

## Integrated architecture
The application remains a local Express service with SQLite as its application record, a local Ethereum-compatible contract as the minimal immutable proof layer, local DID/Ed25519 VC identities, a demo student wallet, and a local explainable document-analysis service. Stage 9 did not change the smart contract, replace the DID/VC or AI implementations, add external services, or add dependencies.

See [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md) for the integrated flow diagram.

## Lifecycle integration
1. Issuer session middleware protects credential issue/revoke, dashboard, recent verification, and AI analysis/history routes.
2. Issue input is validated and normalized before wallet preparation or chain work. Credential ID and hash are generated locally.
3. A VC is created and signed locally before chain submission. If chain anchoring fails, no credential, VC, or student identity row is committed to SQLite.
4. After a successful chain receipt, a single SQLite transaction stores a new student identity (when needed), credential, blockchain metadata, and VC record.
5. Wallet lookup joins each VC to the current SQLite credential status, so revocation is reflected in the wallet.
6. Public verification remains unauthenticated and independently checks local credential hash/status, VC signature and DID/claim binding when a VC exists, and chain proof/revocation.
7. The QR endpoint returns a PNG for `/verify.html?id=<credentialId>`; that page loads the public credential and calls public verification. QR payloads contain an ID URL only, not a key or student fields.
8. Authenticated document analysis uses a private temporary upload, returns document indicators and a deterministic score separately from VC/blockchain checks, records JSON history, and removes the uploaded file.
9. Revocation remains chain-first. SQLite changes to `REVOKED` only after a successful transaction receipt; wallet and public verification then reflect the revoked state.

The AI score does not decide credential validity. The live run demonstrated a document score of 95 alongside a still-`REVOKED` post-revocation credential and blockchain result.

## Integration fixes
- Rejected malformed, empty, overlong, or invalid-year issue fields before DID creation or blockchain submission. This prevents malformed values from being anchored before SQLite rejects them.
- Deferred persistence of a new student identity until the same post-anchor transaction that saves its credential and VC.
- Bound VC claims to the SQLite credential and bound issuer DID/public key and student DID/wallet ID to their registered identity records. Malformed VC keys/proofs now resolve as invalid rather than causing a verifier exception.
- Added non-destructive indexes for VC lookup by credential and wallet, retaining existing schema/data.
- Kept the wallet ownership model at its documented demo level; no cryptocurrency features or production wallet changes were made.

## APIs and database integration
Existing APIs remain in place, including issuer auth/logout, credential issue/list/get/revoke, public verification, QR, dashboard/recent verification, wallet metadata/list/detail/export, and the Stage 8 document analysis/history routes.

Stage 9 added no tables. The database still contains `credentials`, `users`, `verification_logs`, `sessions`, `student_identities`, `verifiable_credentials`, and `ai_analysis_results`. Stage 9 added indexes `idx_vc_credential_created` and `idx_vc_wallet_created`. All application SQL values remain bound parameters. Existing tables declare no foreign-key constraints, but the audit found no orphan VCs, credential-linked analyses, wallet-to-VC relations, or credential-linked verification logs. `UNKNOWN` verification-log rows are intentional not-found events. No schema rebuild or destructive migration was performed.

## Security review
- Issuer routes reject unauthenticated requests; invalid login fails; logout clears the session and protected APIs reject the old cookie.
- Responses checked during the live run contained no private-key fields or configured session/blockchain secrets.
- `.env`, SQLite, source files, local identity JSON, and upload URLs were not served by HTTP.
- Upload middleware enforces supported types, a 10 MB limit, and server-generated filenames. Files are stored outside the public route tree and cleaned after analysis.
- SQL statements use parameters. Frontend analysis and credential data use text-safe DOM APIs; no new `innerHTML` was introduced.
- Chain data contains hashes, issuer address, time, and revoke state only; no student attributes or documents are sent to the chain.
- Wallet APIs remain unauthenticated/demo-level: a wallet ID is not proof of ownership. Private identity keys remain plaintext in a local owner-restricted file, as documented in Stage 7.
- The QR endpoint returned PNGs for valid and revoked credentials. A local QR decoder was not installed, so bitmap payload decoding was not independently performed; the configured target page/API flow was exercised directly.

## Tests performed
- `npm test`: 5 Hardhat/VC tests passed and 4 Stage 8 Node tests passed.
- Backend syntax checks: `server.js`, `database.js`, `aiAuthenticityService.js`, `didService.js`, `verifiableCredentialService.js`, `blockchainService.js`, and `tests/stage8.test.js` passed.
- Live end-to-end used new credential `2f11fe8f-de5e-4e96-a19c-d1bc668f2659` and an existing student wallet. Issuance anchored with transaction `0xc30eb195fe0460a5d23a34da774e28244aa2ee7a6a05b0425e95b3a1f1be8a9a`; VC signature and DID binding passed; wallet listing and JSON export passed.
- Before revocation, public verification returned `VALID` for VC and blockchain. Matching PDF upload produced deterministic score 95 and all five field matches. A changed-degree document generated a new hash, a field mismatch, and a lower score while the credential remained unchanged.
- Revocation transaction `0x1dc2f7d9ff3c192ce9be4522b599ed80a7069810d4d9162f8ed9cd89e3b3561b` succeeded. SQLite, contract, wallet, and public verifier reported `REVOKED`. A new post-revocation AI analysis retained its document score but separately reported blockchain and credential status `REVOKED`.
- Offline-RPC failure probe returned 502 and left zero credentials, VC rows, or student-identity rows in an isolated SQLite database.
- An isolated failed-revocation probe against an unavailable RPC returned 502, left SQLite status/transaction metadata unchanged, and caused public verification to report `BLOCKCHAIN_VERIFICATION_FAILED`, not `REVOKED`.
- Authentication, dashboard counts/recent activity, logout, secret response checks, private-file paths, and upload cleanup were exercised. The test server and isolated failure database were cleaned up; the real on-chain test credential was retained as revoked because contract records cannot be deleted.
- SQLite audit found no orphan relationships. Existing legacy `REVOKED`/`NOT_ANCHORED` records remain unchanged; they predate chain anchoring and were not rewritten.
- `git diff --check` could not run because this workspace directory is not a Git repository.

## Dependency audit
`npm audit --omit=dev` reported 19 runtime dependency advisories: 11 low, 3 moderate, and 5 high. Reported transitive packages include `adm-zip`, `cookie`, `diff`, `elliptic`, `qs`, `serialize-javascript`, `tmp`, `undici`, and `uuid`, primarily through the existing Hardhat 2/solc dependency tree. npm's automatic all-fix suggestion requires a breaking Hardhat 3 upgrade. No dependency was changed or upgraded; this remains a documented dependency risk.

## Remaining limitations
- This is a local capstone/demo system, not production-grade identity, wallet, AI, document forensics, or security infrastructure.
- Student wallet ownership is not authenticated. Local DID private keys are plaintext at rest.
- Legacy credentials may not have a VC or blockchain anchor; existing states were preserved, not retroactively rewritten.
- An on-chain transaction cannot be rolled back if a later local disk/database failure occurs after mining. Input is validated first and local persistence is atomic; an operator still needs to reconcile a rare post-anchor persistence failure.
- Scanned images have no OCR, PDF/image heuristics can be spoofed, and a high analysis score is not legal proof of authenticity.
- The QR image bytes were generated and both public states were verified, but payload decoding was unavailable without an installed local decoder.
- Runtime dependency advisories remain as recorded above.
