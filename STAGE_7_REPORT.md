# Stage 7 Report

## Overview
This stage adds a local DID and signed Verifiable Credential layer to the existing SQLite + blockchain academic credential system. Issuance keeps the existing issuer authorization and blockchain anchoring flow; local credential, blockchain metadata, and VC records are committed together in a SQLite transaction after anchoring succeeds.

## DID architecture
- DID format: `did:academic:<identifier>`; this is a local demonstration method, not a network-resolvable DID method.
- Issuer and student identities use Node.js `crypto` Ed25519 key pairs.
- Public identity metadata is stored in SQLite. Private keys are held in `data/local-identities.json`, which is ignored by Git and restricted to owner read/write permissions on Linux.
- Private keys are never returned through APIs or frontend code.

## VC structure
Newly issued VCs contain:
- `@context`
- `type`
- `issuer`
- `credentialSubject`
- `credentialId`
- `issuanceDate`
- `credentialStatus`
- `proof` with an Ed25519 signature over the unsigned VC payload

## Signing algorithm
- `ed25519`
- Signature is created over recursively key-sorted canonical JSON for the unsigned VC.
- Verification checks the signature and that the VC credential ID and subject claims match the linked SQLite credential.

## Wallet architecture
- Local student wallets store a DID and public key, with VC records linked by wallet ID.
- The wallet page accepts a wallet ID, shows current SQLite/blockchain status, and supports downloading VC JSON.
- Existing credentials created before Stage 7 remain verifiable through the prior hash and blockchain checks; they do not have a retroactively generated VC.

## API endpoints
- `POST /api/wallet/create` creates or returns a local wallet from `studentName` and/or `walletId`.
- `GET /api/wallet/me?walletId=...` returns wallet metadata.
- `GET /api/wallet/credentials?walletId=...` lists signed credentials for a wallet.
- `GET /api/wallet/credentials/:id` returns a wallet VC record.
- `GET /api/wallet/credentials/:id/export` downloads the VC JSON.

## Database changes
- `users`: issuer DID and issuer public key fields
- `student_identities`: wallet identifier, DID, public key, created time
- `verifiable_credentials`: credential linkage, issuer DID, student DID, VC payload, signature, created time

## Security considerations
- No private keys are returned from APIs.
- The local private-key JSON is plaintext at rest; filesystem permissions and Git ignore rules are only suitable for a local demo, not a multi-user or production host.
- Wallet APIs and VC detail/export routes do not authenticate wallet ownership. A wallet ID is not proof of student control.
- No blockchain private key is stored in the VC.
- No student private data is written to the blockchain.
- Public verification remains unauthenticated.

## Test results
- `node --check server.js`, `database.js`, `didService.js`, and `verifiableCredentialService.js` passed.
- `npm test` passed: 4 tests, including valid signature, key-order canonicalization, tamper rejection, and missing-proof rejection.
- SQLite initialization check confirmed `student_identities` and `verifiable_credentials` tables.

## Limitations
- This is a local, standards-inspired implementation for demonstration rather than a production W3C DID/VC deployment.
- It does not use an external identity network or remote wallet service.
- Student wallet access is local/demo-oriented rather than a full browser-secure wallet implementation; there is no wallet authentication, encrypted key storage, key recovery, or key rotation.
- Credential revocation is reflected from SQLite/blockchain status; the originally signed VC payload itself is not re-signed on revoke.
- New Stage 7 behavior has unit coverage for signing, but the full HTTP issuance-to-wallet workflow has not been exercised end-to-end in this session.
