const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { spawn } = require('node:child_process');
const net = require('node:net');
const Database = require('better-sqlite3');
const { test } = require('node:test');
require('dotenv').config();

const {
  MAX_DOCUMENT_BYTES,
  UPLOAD_DIRECTORY,
  createUploadFilename,
  inspectJpeg,
  analyzeDocument
} = require('../aiAuthenticityService');

function pngCrc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(pngCrc32(Buffer.concat([typeBuffer, data])));
  return Buffer.concat([length, typeBuffer, data, crc]);
}

function makePng(width = 320, height = 320) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 2;
  header[10] = 0;
  header[11] = 0;
  header[12] = 0;
  const row = Buffer.alloc(width * 3 + 1, 255);
  for (let index = 0; index < height; index += 1) row[index * (width * 3 + 1)] = 0;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk('IHDR', header),
    pngChunk('IDAT', zlib.deflateSync(Buffer.concat(Array.from({ length: height }, () => row)))),
    pngChunk('IEND', Buffer.alloc(0))
  ]);
}

function pdfString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function makePdf(lines) {
  const content = ['BT', '/F1 12 Tf', '50 740 Td'];
  lines.forEach((line, index) => {
    if (index) content.push('0 -20 Td');
    content.push(`(${pdfString(line)}) Tj`);
  });
  content.push('ET');
  const stream = content.join('\n');
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`
  ];
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(Buffer.byteLength(pdf));
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.from(pdf, 'binary');
}

function makeJpeg() {
  const segment = (marker, data) => {
    const length = Buffer.alloc(2);
    length.writeUInt16BE(data.length + 2);
    return Buffer.concat([Buffer.from([0xff, marker]), length, data]);
  };
  const sof = Buffer.from([8, 0x01, 0x40, 0x01, 0x40, 1, 1, 0x11, 0]);
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    segment(0xe0, Buffer.from('JFIF\0', 'ascii')),
    segment(0xc0, sof),
    segment(0xda, Buffer.from([1, 1, 0, 0, 63, 0])),
    Buffer.from([0x00, 0x01, 0xff, 0xd9])
  ]);
}

function fixtureCredential() {
  return {
    id: 'credential-stage8-fixture-01',
    studentName: 'Morgan Example',
    degree: 'Bachelor of Science',
    university: 'North Valley University',
    graduationYear: 2025,
    status: 'VALID',
    hash: 'a'.repeat(64)
  };
}

function createTempFile(directory, filename, data) {
  const filePath = path.join(directory, filename);
  fs.writeFileSync(filePath, data);
  return filePath;
}

async function findAvailablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForServer(baseUrl, child) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline && child.exitCode === null) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch (error) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error('Temporary test server did not become ready.');
}

function formWithDocument(contents, type, filename, credentialId) {
  const form = new FormData();
  if (credentialId) form.append('credentialId', credentialId);
  form.append('document', new Blob([contents], { type }), filename);
  return form;
}

function assertNoPrivateFields(value) {
  if (Array.isArray(value)) return value.forEach(assertNoPrivateFields);
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      assert.doesNotMatch(key, /private.?key|secret.?key/i);
      assertNoPrivateFields(child);
    }
  }
}

test('PDF field matching, SHA-256 and deterministic scoring; changed claims are flagged', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage8-unit-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const credential = fixtureCredential();
  const matchingPdf = makePdf([
    `Student Name: ${credential.studentName}`,
    `Degree: ${credential.degree}`,
    `University: ${credential.university}`,
    `Graduation Year: ${credential.graduationYear}`,
    `Credential ID: ${credential.id}`,
    'Signature: Registrar'
  ]);
  const matchingPath = createTempFile(directory, 'matching.pdf', matchingPdf);
  const first = await analyzeDocument({ filePath: matchingPath, declaredMimeType: 'application/pdf', originalName: 'matching.pdf', credential });
  const second = await analyzeDocument({ filePath: matchingPath, declaredMimeType: 'application/pdf', originalName: 'matching.pdf', credential });
  assert.equal(first.fileHash, crypto.createHash('sha256').update(matchingPdf).digest('hex'));
  assert.equal(first.score, second.score);
  assert.equal(first.classification, second.classification);
  assert.equal(first.textExtraction.available, true);
  assert.equal(first.fieldMatches.studentName.match, true);
  assert.equal(first.fieldMatches.credentialId.match, true);
  assert.equal(first.classification, 'HIGH_CONFIDENCE');

  const changedPdf = makePdf([
    `Student Name: ${credential.studentName}`,
    'Degree: Altered Qualification',
    `University: ${credential.university}`,
    `Graduation Year: ${credential.graduationYear}`,
    `Credential ID: ${credential.id}`,
    'Signature: Registrar'
  ]);
  const changedPath = createTempFile(directory, 'changed.pdf', changedPdf);
  const changed = await analyzeDocument({ filePath: changedPath, declaredMimeType: 'application/pdf', originalName: 'changed.pdf', credential });
  assert.notEqual(changed.fileHash, first.fileHash);
  assert.equal(changed.fieldMatches.degree.match, false);
  assert.equal(changed.classification, 'REVIEW_REQUIRED');
  assert.ok(changed.warnings.some((warning) => warning.includes('field')));

  const emptyPdf = makePdf([]);
  const emptyPath = createTempFile(directory, 'empty-text.pdf', emptyPdf);
  const empty = await analyzeDocument({ filePath: emptyPath, declaredMimeType: 'application/pdf', originalName: 'empty-text.pdf', credential });
  assert.equal(empty.textExtraction.available, false);
  assert.equal(empty.fieldMatches.studentName.extractionAvailable, false);
  assert.equal(empty.fieldMatches.studentName.detected, null);
  assert.ok(empty.checks.some((check) => check.id === 'credential-field-match' && check.status === 'unavailable'));
});

test('PNG analysis reports no text extraction and scores low resolution conservatively', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage8-image-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const pngPath = createTempFile(directory, 'scan.png', makePng(320, 320));
  const result = await analyzeDocument({ filePath: pngPath, declaredMimeType: 'image/png', originalName: 'scan.png', credential: fixtureCredential() });
  assert.equal(result.fileType, 'image/png');
  assert.equal(result.metadata.width, 320);
  assert.equal(result.textExtraction.available, false);
  assert.equal(result.fieldMatches.studentName.match, false);
  assert.equal(result.fieldMatches.studentName.extractionAvailable, false);
  assert.equal(result.signatureIndicator.status, 'unassessed');
  assert.equal(result.classification, 'REVIEW_REQUIRED');

  const tinyPath = createTempFile(directory, 'tiny.png', makePng(32, 32));
  const tiny = await analyzeDocument({ filePath: tinyPath, declaredMimeType: 'image/png', originalName: 'tiny.png', credential: fixtureCredential() });
  assert.ok(tiny.score < result.score);
  assert.ok(tiny.warnings.some((warning) => warning.includes('dimensions')));
});

test('JPEG dimensions and safe random server filenames are parsed without original path use', () => {
  const jpeg = makeJpeg();
  const image = inspectJpeg(jpeg);
  assert.equal(image.format, 'JPEG');
  assert.equal(image.width, 320);
  assert.equal(image.height, 320);
  assert.equal(image.structureValid, true);
  const filename = createUploadFilename('image/jpeg');
  assert.match(filename, /^[0-9a-f-]{36}\.jpg$/i);
  assert.equal(filename.includes('..'), false);
});

test('upload API enforces authentication, type and size limits, persists summary, and removes staged files', async (t) => {
  if (!process.env.ISSUER_USERNAME || !process.env.ISSUER_PASSWORD || !process.env.SESSION_SECRET) {
    t.skip('Local issuer and session configuration are required for HTTP integration tests.');
    return;
  }

  fs.mkdirSync(UPLOAD_DIRECTORY, { recursive: true, mode: 0o700 });
  const beforeFiles = new Set(fs.readdirSync(UPLOAD_DIRECTORY));
  const identityStorePath = path.join(__dirname, '..', 'data', 'local-identities.json');
  const identityStoreBefore = fs.readFileSync(identityStorePath);
  const testDatabaseDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage8-http-db-'));
  const port = await findAvailablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const testDatabasePath = path.join(testDatabaseDirectory, 'credentials.db');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(port), CREDENTIAL_DATABASE_FILE: testDatabasePath, BLOCKCHAIN_RPC_URL: 'http://127.0.0.1:1' },
    stdio: 'ignore'
  });
  t.after(() => {
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      return new Promise((resolve) => child.once('exit', () => {
        fs.rmSync(testDatabaseDirectory, { recursive: true, force: true });
        resolve();
      }));
    }
    fs.rmSync(testDatabaseDirectory, { recursive: true, force: true });
    return undefined;
  });
  await waitForServer(baseUrl, child);

  const unauthorized = await fetch(`${baseUrl}/api/ai/analyze-document`, {
    method: 'POST',
    body: formWithDocument(makePng(), 'image/png', 'scan.png')
  });
  assert.equal(unauthorized.status, 401);

  const login = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: process.env.ISSUER_USERNAME, password: process.env.ISSUER_PASSWORD })
  });
  assert.equal(login.status, 200);
  const setCookie = login.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Lax/i);
  if (process.env.NODE_ENV === 'production') assert.match(setCookie, /Secure/i);
  const cookie = setCookie.split(';')[0];
  const headers = { cookie };

  const oversizedLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'issuer', password: 'x'.repeat(2048) })
  });
  assert.equal(oversizedLogin.status, 401);

  const malformedJson = await fetch(`${baseUrl}/api/credentials`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: '{"studentName":'
  });
  assert.equal(malformedJson.status, 400);
  assert.equal((await malformedJson.json()).error, 'Malformed JSON request.');

  const arbitraryWallet = await fetch(`${baseUrl}/api/wallet/create`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ walletId: 'attacker-controlled-wallet', studentName: 'attacker-controlled-student' })
  });
  assert.equal(arbitraryWallet.status, 404);
  assert.equal((await fetch(`${baseUrl}/api/wallet/me?walletId=attacker-controlled-wallet`)).status, 404);
  assert.deepEqual(fs.readFileSync(identityStorePath), identityStoreBefore);

  const malformedCredential = await fetch(`${baseUrl}/api/credentials`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ studentName: { unexpected: true }, degree: 'BSc', university: 'Local University', graduationYear: 2026 })
  });
  assert.equal(malformedCredential.status, 400);
  const credentialsAfterRejectedIssue = await fetch(`${baseUrl}/api/credentials`, { headers });
  assert.equal(credentialsAfterRejectedIssue.status, 200);
  assert.deepEqual(await credentialsAfterRejectedIssue.json(), []);

  const failedIssue = await fetch(`${baseUrl}/api/credentials`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({
      studentName: "SQL'); DROP TABLE credentials;--",
      degree: 'BSc',
      university: 'Local University',
      graduationYear: 2026
    })
  });
  assert.equal(failedIssue.status, 502);
  const databaseAfterFailedIssue = new Database(testDatabasePath);
  assert.equal(databaseAfterFailedIssue.prepare('SELECT COUNT(*) AS count FROM credentials').get().count, 0);
  assert.equal(databaseAfterFailedIssue.prepare('SELECT COUNT(*) AS count FROM verifiable_credentials').get().count, 0);
  assert.equal(databaseAfterFailedIssue.prepare('SELECT COUNT(*) AS count FROM student_identities').get().count, 0);
  databaseAfterFailedIssue.close();
  assert.deepEqual(fs.readFileSync(identityStorePath), identityStoreBefore);

  const revokeCredential = {
    id: 'stage8-revoke-failure-fixture',
    studentName: 'Failure Fixture',
    degree: 'BSc',
    university: 'Local University',
    graduationYear: 2026,
    issuedAt: '2026-01-01T00:00:00.000Z'
  };
  const revokeHash = crypto.createHash('sha256')
    .update(`${revokeCredential.studentName}|${revokeCredential.degree}|${revokeCredential.university}|${revokeCredential.graduationYear}|${revokeCredential.issuedAt}`)
    .digest('hex');
  const seedDatabase = new Database(testDatabasePath);
  seedDatabase.prepare(`
    INSERT INTO credentials (
      id, student_name, degree, university, graduation_year, issued_at,
      hash, status, blockchain_tx_hash, blockchain_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'VALID', '0xprevious-transaction', 'ANCHORED')
  `).run(
    revokeCredential.id,
    revokeCredential.studentName,
    revokeCredential.degree,
    revokeCredential.university,
    revokeCredential.graduationYear,
    revokeCredential.issuedAt,
    revokeHash
  );
  seedDatabase.close();
  const normalQr = await fetch(`${baseUrl}/api/credentials/${revokeCredential.id}/qr`);
  assert.equal(normalQr.status, 200);
  const spoofedQr = await fetch(`${baseUrl}/api/credentials/${revokeCredential.id}/qr`, {
    headers: { 'x-forwarded-host': 'attacker.invalid', 'x-forwarded-proto': 'https' }
  });
  assert.equal(spoofedQr.status, 200);
  assert.deepEqual(Buffer.from(await spoofedQr.arrayBuffer()), Buffer.from(await normalQr.arrayBuffer()));
  const failedRevoke = await fetch(`${baseUrl}/api/credentials/${revokeCredential.id}/revoke`, {
    method: 'PATCH', headers
  });
  assert.equal(failedRevoke.status, 502);
  const failedRevokeBody = await failedRevoke.json();
  assert.equal(failedRevokeBody.credential.status, 'VALID');
  assert.equal(failedRevokeBody.credential.blockchainStatus, 'ANCHORED');
  assert.equal(failedRevokeBody.credential.blockchainTxHash, '0xprevious-transaction');
  const checkDatabase = new Database(testDatabasePath);
  const storedAfterFailedRevoke = checkDatabase.prepare(`
    SELECT status, blockchain_tx_hash AS blockchainTxHash, blockchain_status AS blockchainStatus
    FROM credentials WHERE id = ?
  `).get(revokeCredential.id);
  checkDatabase.close();
  assert.deepEqual(storedAfterFailedRevoke, {
    status: 'VALID',
    blockchainTxHash: '0xprevious-transaction',
    blockchainStatus: 'ANCHORED'
  });
  const publicAfterFailedRevoke = await fetch(`${baseUrl}/api/verify/${revokeHash}`);
  assert.equal(publicAfterFailedRevoke.status, 200);
  const publicAfterFailedRevokeBody = await publicAfterFailedRevoke.json();
  assert.notEqual(publicAfterFailedRevokeBody.result, 'REVOKED');
  assert.equal(publicAfterFailedRevokeBody.result, 'BLOCKCHAIN_VERIFICATION_FAILED');

  const unsupported = await fetch(`${baseUrl}/api/ai/analyze-document`, {
    method: 'POST', headers,
    body: formWithDocument(Buffer.from('not an academic document'), 'text/plain', '../../unsafe.txt')
  });
  assert.equal(unsupported.status, 415);

  const tooLarge = await fetch(`${baseUrl}/api/ai/analyze-document`, {
    method: 'POST', headers,
    body: formWithDocument(Buffer.alloc(MAX_DOCUMENT_BYTES + 1), 'application/pdf', 'large.pdf')
  });
  assert.equal(tooLarge.status, 413);

  const fixture = makePdf(['Student Name: Example', 'Signature: Registrar']);
  const response = await fetch(`${baseUrl}/api/ai/analyze-document`, {
    method: 'POST', headers,
    body: formWithDocument(fixture, 'application/pdf', '../../randomized.pdf')
  });
  assert.equal(response.status, 201);
  const analysis = await response.json();
  assert.equal(analysis.fileHash, crypto.createHash('sha256').update(fixture).digest('hex'));
  assert.equal(typeof analysis.score, 'number');
  assert.equal(analysis.cryptographicVerification.vcSignature.result, 'NOT_AVAILABLE');
  assert.equal(analysis.cryptographicVerification.blockchainProof.result, 'NOT_AVAILABLE');
  assert.doesNotMatch(JSON.stringify(analysis), /academic-credential-verification-stage8|privateKey|secretKey|Example/);
  assertNoPrivateFields(analysis);

  const pngResponse = await fetch(`${baseUrl}/api/ai/analyze-document`, {
    method: 'POST', headers,
    body: formWithDocument(makePng(), 'image/png', 'scan.png')
  });
  assert.equal(pngResponse.status, 201);
  const pngAnalysis = await pngResponse.json();
  assert.equal(pngAnalysis.fileType, 'image/png');
  assert.equal(pngAnalysis.documentAnalysis.textExtraction.available, false);
  assert.equal(pngAnalysis.documentAnalysis.fieldMatches, null);

  const mismatchedType = await fetch(`${baseUrl}/api/ai/analyze-document`, {
    method: 'POST', headers,
    body: formWithDocument(makePng(), 'application/pdf', 'mismatch.pdf')
  });
  assert.equal(mismatchedType.status, 415);

  const malformedPdf = await fetch(`${baseUrl}/api/ai/analyze-document`, {
    method: 'POST', headers,
    body: formWithDocument(Buffer.from('%PDF-1.4\n%%EOF\n'), 'application/pdf', 'malformed.pdf')
  });
  assert.equal(malformedPdf.status, 201);
  const malformedPdfBody = await malformedPdf.json();
  assert.equal(malformedPdfBody.documentAnalysis.metadata.pages, null);
  assert.equal(malformedPdfBody.documentAnalysis.textExtraction.available, false);
  assert.ok(malformedPdfBody.warnings.length > 0);

  const historyResponse = await fetch(`${baseUrl}/api/ai/analysis/${encodeURIComponent(analysis.id)}`, { headers });
  assert.equal(historyResponse.status, 200);
  const history = await historyResponse.json();
  assert.equal(history.analysis.fileHash, analysis.fileHash);
  assert.equal(history.analysis.score, analysis.score);

  const publicHistory = await fetch(`${baseUrl}/api/ai/analysis/${encodeURIComponent(analysis.id)}`);
  assert.equal(publicHistory.status, 401);
  const publicCredentialHistory = await fetch(`${baseUrl}/api/credentials/private-test-credential/ai-analysis`);
  assert.equal(publicCredentialHistory.status, 401);
  const missingCredential = await fetch(`${baseUrl}/api/credentials/not-a-credential/revoke`, {
    method: 'PATCH', headers
  });
  assert.equal(missingCredential.status, 404);
  const fileResponse = await fetch(`${baseUrl}/uploads/${encodeURIComponent(analysis.fileHash)}.pdf`);
  assert.equal(fileResponse.status, 404);
  for (const privatePath of ['/.env', '/credentials.db', '/database.js', '/data/local-identities.json']) {
    const privateResponse = await fetch(`${baseUrl}${privatePath}`);
    assert.equal(privateResponse.status, 404, `${privatePath} must not be served over HTTP`);
  }

  const remaining = fs.readdirSync(UPLOAD_DIRECTORY).filter((filename) => !beforeFiles.has(filename));
  assert.deepEqual(remaining, []);

  const logout = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST', headers });
  assert.equal(logout.status, 200);
  const protectedAfterLogout = await fetch(`${baseUrl}/api/credentials`, { headers });
  assert.equal(protectedAfterLogout.status, 401);
});
