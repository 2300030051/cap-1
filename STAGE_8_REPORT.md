# Stage 8 Report: AI-Assisted Document Authenticity Analysis

## Scope and architecture
Stage 8 adds a local, explainable document-analysis module beside the existing Express, SQLite, issuer-session, DID/VC, and blockchain verification flows. It does not modify the smart contract or the existing public verification response. Analysis initiation and analysis history require issuer authentication; public verification does not return analysis history or uploaded documents.

The analysis is deterministic and rule-based, not a trained AI/forensic model. No document or extracted content is sent to a cloud service. A returned score is a risk indicator, not proof of physical-document authenticity.

> AI authenticity analysis provides risk indicators and an explainable confidence assessment; it does not mathematically prove that a physical academic document is genuine.

## Upload flow and security
- `POST /api/ai/analyze-document` accepts one multipart `document`, with optional `credentialId`.
- Accepted types: PDF, PNG, JPEG. Both declared MIME and file signature are checked; the original extension must agree as well.
- Upload size is limited to 10 MB; field, part, and file count limits are enforced.
- Multer generates a UUID filename with a server-selected extension. Original names are never used for a path.
- Temporary files are written under the OS temporary directory in a directory restricted to owner access, then removed in a `finally` block.
- The app does not publicly mount the upload directory. It stores only analysis JSON and file hash in SQLite, not document bytes or extracted full text.
- Local PDF tools are run without a shell, with a restricted environment, bounded output, and a timeout. They execute as the app user, so the app should run as an unprivileged local account.
- API/UI output excludes extracted document text and server filesystem paths. Full extracted text is transient in server memory during credential comparison and is not logged.

## Analysis pipeline
1. Validate upload size, declared MIME, filename extension, and byte-level file signature.
2. Compute SHA-256 from the actual file bytes.
3. For PDFs, inspect header/EOF/object balance and active-content markers; use local Poppler `pdfinfo` for pages/metadata and `pdftotext` for layout-preserving text extraction when available.
4. For PNG, parse dimensions, chunk CRCs, IEND, text metadata, and trailing bytes. For JPEG, parse dimensions, EXIF presence, metadata segments, EOI, and trailing bytes.
5. Compare extracted PDF text against credential fields when a credential ID is supplied. Raster images do not have OCR in this stage; they explicitly report extraction as unavailable.
6. Report signature-related text markers for PDFs or an unassessed visual signature for images. Neither authenticates handwriting.
7. Verify the existing Stage 7 VC signature and credential binding, and query the existing blockchain proof. These are reported separately from the document score.
8. Persist structured result JSON, score, classification, file hash, and credential linkage. Delete the uploaded file.

## Scoring formula
The deterministic score is:

`round(earned applicable points / applicable points * 100)`

Checks use fixed weights:
- File signature/type and SHA-256 calculation: 15 points.
- Structural consistency: 20 points.
- Metadata consistency/availability: 10 points.
- Non-empty local text extraction: 15 points.
- Credential comparison, when requested: 5 points for each of five fields (student name, degree, university, graduation year, credential ID), only when extraction is available.
- Signature-related document indicator: 15 points; unavailable markers or low-resolution scans receive fewer points.

Crypto checks do not change the document score. A mismatch in at least two fields, suspicious structure, editing-software metadata, or inconsistent modification time classifies the result as `SUSPICIOUS`. Other scores of 85 or higher classify as `HIGH_CONFIDENCE`; scores from 55 to 84 classify as `REVIEW_REQUIRED`; lower scores classify as `SUSPICIOUS`. A single field mismatch or unavailable text/visual check requires review. The score is an explainable indicator, not a calibrated probability.

## Credential matching
When a credential ID is provided, the service loads student name, degree, university, graduation year, and credential ID from SQLite. Extracted PDF text is compared case-insensitively after Unicode normalization. Labelled lines report a detected value; a value also present in the text can match without a label. If extraction is empty or unavailable, each field reports `extractionAvailable: false`, `detected: null`, and no match is inferred. PNG/JPEG do not receive OCR in this stage.

## Signature and cryptographic verification
- Document signature analysis only looks for signature-related text markers in extracted PDFs. Images report visual signature analysis as unassessed. Neither detects or authenticates handwriting.
- VC cryptographic signature uses the existing Stage 7 Ed25519 verifier and separately checks that signed claims match the SQLite credential.
- Blockchain verification uses the existing `blockchainService` proof/hash/revocation check.
- Credential status is shown separately. None of these checks proves the physical document itself is genuine.

## Database changes
`ai_analysis_results` stores: analysis ID, optional credential ID, SHA-256, detected MIME type, score, classification, structured analysis JSON, and creation timestamp. It stores neither uploaded file bytes nor full extracted text.

## APIs
- `POST /api/ai/analyze-document` (issuer session required): multipart field `document`, optional text field `credentialId`; returns structured document analysis, independent cryptographic results, and assessment.
- `GET /api/ai/analysis/:id` (issuer session required): retrieves one stored analysis.
- `GET /api/credentials/:id/ai-analysis` (issuer session required): retrieves a credential's analysis history.

Public `/api/verify/:hash` remains unchanged and does not expose AI analysis records or documents.

## UI
The issuer dashboard adds a credential selector, document picker, analysis action, score/classification, indicators, warnings, field matches, a separate crypto result list, expandable safe detail summary, and analysis-history buttons. All uploaded-document analysis values are rendered with text nodes/textContent, not `innerHTML`.

## Dependencies and local requirements
- Added `multer` for multipart parsing.
- PDF metadata/text extraction uses the existing Fedora Poppler executables `pdfinfo` and `pdftotext`; if unavailable, the response reports unavailable extraction/metadata and does not invent text matches.
- PNG/JPEG checks use Node built-ins; no image processing or OCR dependency was added.
- No model training, external AI service, or smart-contract change.

## Tests and validation
- `npm test` runs the existing Hardhat/VC tests and `node --test tests/*.test.js`.
- Stage 8 tests generate controlled PDF, PNG, and JPEG fixtures locally; test deterministic scores, changed field/hash indicators, dimensions and image structure, MIME mismatch, unsupported type, >10 MB rejection, unauthenticated rejection, server-generated filenames, private HTTP paths, JSON-only history, and temporary-file cleanup. The HTTP test server uses a temporary isolated SQLite database that is deleted afterward, leaving application data untouched.
- Final `npm test` result: 4 existing Hardhat/VC tests passed and 4 Stage 8 Node tests passed.
- Backend `node --check` passed for `server.js`, `database.js`, `aiAuthenticityService.js`, `verifiableCredentialService.js`, `blockchainService.js`, and the Stage 8 test file.
- Live end-to-end test selected existing credential `ab307f71-2f53-48e7-a384-6de7d2f49791`, which was already `REVOKED` in SQLite and chain. No credential state was changed. A generated PDF matched all five fields, scored 95 deterministically on repeated upload, and reported VC signature/binding `VALID` plus blockchain/status `REVOKED`. A modified-degree PDF produced a different SHA-256, degree mismatch, and lower score. Analysis history was stored, public verification remained `REVOKED`, private files and upload URLs returned 404, and temporary files were removed.
- `git diff --check` cannot run in this workspace because the directory is not a Git repository.

## Known limitations
- This is a local capstone/demo risk-indicator module, not production-grade AI or forensic examination.
- No OCR is provided for scanned images; PDF image-only pages may also yield no text.
- The current local database has no valid, anchored credential with a stored VC available for a live test. The live integration used the pre-existing revoked VC-backed record and verified the expected revoked state; the regular contract/VC regression tests still pass.
- PDF keyword checks and metadata are heuristic and can be absent, edited, or spoofed.
- PNG/JPEG analysis verifies basic structure and metadata only; it does not detect sophisticated compositing or localized editing.
- Signature checks do not prove that a handwritten signature is genuine.
- Metadata such as editor names is only a warning indicator and does not establish tampering.
- Local Poppler executables must be installed and patched by the host OS.
- Temporary input is processed by local system PDF tools as an unprivileged process; isolation beyond that is not implemented.
- The score is not a probability, legal conclusion, or guarantee. Human review remains necessary.
