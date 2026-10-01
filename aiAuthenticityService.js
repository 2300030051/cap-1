const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const {
  verifyCredentialVC,
  verifyCredentialBinding
} = require('./verifiableCredentialService');
const { checkBlockchainValidity } = require('./blockchainService');

const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;
const MAX_TEXT_BYTES = 1024 * 1024;
const UPLOAD_DIRECTORY = path.join(os.tmpdir(), 'academic-credential-verification-stage8');
const SUPPORTED_TYPES = {
  'application/pdf': '.pdf',
  'image/png': '.png',
  'image/jpeg': '.jpg'
};

function ensureUploadDirectory() {
  fs.mkdirSync(UPLOAD_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(UPLOAD_DIRECTORY, 0o700);
  return UPLOAD_DIRECTORY;
}

function createUploadFilename(mimetype) {
  const extension = SUPPORTED_TYPES[mimetype];
  if (!extension) {
    throw new Error('Unsupported document type.');
  }
  return `${crypto.randomUUID()}${extension}`;
}

function detectFileType(buffer) {
  if (buffer.length >= 5 && buffer.subarray(0, 5).toString('ascii') === '%PDF-') {
    return { mimeType: 'application/pdf', extension: '.pdf' };
  }
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    return { mimeType: 'image/png', extension: '.png' };
  }
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { mimeType: 'image/jpeg', extension: '.jpg' };
  }
  return null;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function inspectPng(buffer) {
  let offset = 8;
  let width = null;
  let height = null;
  let sawHeader = false;
  let sawEnd = false;
  let crcErrors = 0;
  const metadataTexts = [];
  const chunkTypes = [];

  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const chunkEnd = dataEnd + 4;
    if (dataEnd > buffer.length || chunkEnd > buffer.length) break;

    const data = buffer.subarray(dataStart, dataEnd);
    const expectedCrc = buffer.readUInt32BE(dataEnd);
    if (crc32(buffer.subarray(offset + 4, dataEnd)) !== expectedCrc) crcErrors += 1;
    chunkTypes.push(type);

    if (!sawHeader) {
      sawHeader = type === 'IHDR' && length === 13;
      if (sawHeader) {
        width = data.readUInt32BE(0);
        height = data.readUInt32BE(4);
      }
    }

    if (type === 'tEXt' || type === 'iTXt') {
      metadataTexts.push(data.toString('latin1'));
    }

    offset = chunkEnd;
    if (type === 'IEND') {
      sawEnd = length === 0;
      break;
    }
  }

  const trailingBytes = sawEnd ? buffer.length - offset : 0;
  return {
    format: 'PNG',
    width,
    height,
    structureValid: sawHeader && sawEnd && crcErrors === 0 && trailingBytes === 0,
    crcErrors,
    trailingBytes,
    metadata: metadataTexts.join('\n'),
    chunkTypes,
    imageCount: 1
  };
}

function inspectJpeg(buffer) {
  let offset = 2;
  let width = null;
  let height = null;
  let sawEnd = false;
  let exifPresent = false;
  const metadataSegments = [];
  const sofMarkers = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

  while (offset < buffer.length) {
    if (buffer[offset] !== 0xff) break;
    while (buffer[offset] === 0xff) offset += 1;
    const marker = buffer[offset];
    offset += 1;

    if (marker === 0xd9) {
      sawEnd = true;
      break;
    }
    if (marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > buffer.length) break;

    const segmentLength = buffer.readUInt16BE(offset);
    if (segmentLength < 2 || offset + segmentLength > buffer.length) break;
    const dataStart = offset + 2;
    const dataEnd = offset + segmentLength;
    const data = buffer.subarray(dataStart, dataEnd);

    if (sofMarkers.has(marker) && data.length >= 5) {
      height = data.readUInt16BE(1);
      width = data.readUInt16BE(3);
    }
    if (marker === 0xe1 && data.subarray(0, 6).toString('ascii') === 'Exif\0\0') exifPresent = true;
    if (marker === 0xed || marker === 0xfe || marker === 0xe1) metadataSegments.push(data.toString('latin1'));
    offset = dataEnd;
  }

  const eoiOffset = buffer.lastIndexOf(Buffer.from([0xff, 0xd9]));
  const trailingBytes = eoiOffset >= 0 ? buffer.length - eoiOffset - 2 : 0;
  sawEnd = sawEnd || eoiOffset >= 0;
  return {
    format: 'JPEG',
    width,
    height,
    structureValid: sawEnd && width !== null && height !== null && trailingBytes === 0,
    exifPresent,
    trailingBytes,
    metadata: metadataSegments.join('\n'),
    imageCount: 1
  };
}

function runLocalTool(command, args, maxBytes, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    ensureUploadDirectory();
    const child = spawn(command, args, {
      cwd: UPLOAD_DIRECTORY,
      env: { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C' },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const stdout = [];
    const stderr = [];
    let received = 0;
    let settled = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);

    const collect = (target) => (chunk) => {
      received += chunk.length;
      if (received > maxBytes) {
        child.kill('SIGKILL');
        return;
      }
      target.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (received > maxBytes) return reject(new Error('Local document tool output exceeded its limit.'));
      if (signal) return reject(new Error('Local document tool timed out or was terminated.'));
      if (code !== 0) return reject(new Error(Buffer.concat(stderr).toString('utf8').slice(0, 500) || 'Local document tool failed.'));
      resolve({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
  });
}

function extractPdfDate(value) {
  if (!value) return null;
  const parsed = Date.parse(value.replace(/^D:/, '').replace(/([+-]\d{2})'?(\d{2})'?$/, '$1:$2'));
  return Number.isNaN(parsed) ? null : parsed;
}

async function inspectPdf(filePath, buffer) {
  const rawText = buffer.toString('latin1');
  const headerValid = /^%PDF-\d\.\d/.test(rawText);
  const eofValid = /%%EOF\s*$/.test(rawText);
  const objectCount = (rawText.match(/\b\d+\s+\d+\s+obj\b/g) || []).length;
  const endObjectCount = (rawText.match(/\bendobj\b/g) || []).length;
  const activeContent = [];
  for (const [pattern, label] of [[/\/JavaScript\b|\/JS\b/g, 'JavaScript'], [/\/OpenAction\b/g, 'OpenAction'], [/\/Launch\b/g, 'Launch action'], [/\/EmbeddedFile\b/g, 'embedded file'], [/\/AA\b/g, 'additional action']]) {
    if (pattern.test(rawText)) activeContent.push(label);
  }
  const imageCount = (rawText.match(/\/Subtype\s*\/Image\b/g) || []).length;

  let info = null;
  let text = null;
  const extractionWarnings = [];
  try {
    const result = await runLocalTool('pdfinfo', ['-isodates', filePath], 256 * 1024);
    info = result.stdout.toString('utf8');
  } catch (error) {
    extractionWarnings.push('PDF metadata inspection unavailable from local pdfinfo.');
  }

  try {
    const result = await runLocalTool('pdftotext', ['-layout', '-enc', 'UTF-8', filePath, '-'], MAX_TEXT_BYTES);
    text = result.stdout.toString('utf8').replace(/\0/g, '').slice(0, MAX_TEXT_BYTES);
  } catch (error) {
    extractionWarnings.push('PDF text extraction unavailable from local pdftotext.');
  }

  const readInfo = (label) => {
    const match = info && info.match(new RegExp(`^${label}:\\s*(.*)$`, 'mi'));
    return match ? match[1].trim() : null;
  };
  const pages = Number(readInfo('Pages')) || null;
  const creationDate = readInfo('CreationDate');
  const modificationDate = readInfo('ModDate');
  const creationTime = extractPdfDate(creationDate);
  const modificationTime = extractPdfDate(modificationDate);
  const metadataInconsistent = Boolean(creationTime && modificationTime && modificationTime < creationTime);
  const structureValid = headerValid && eofValid && objectCount > 0 && objectCount === endObjectCount && Boolean(info) && pages !== null && pages > 0 && pages <= 100;
  const suspiciousStructure = objectCount !== endObjectCount || activeContent.length > 0;

  return {
    format: 'PDF',
    headerValid,
    eofValid,
    pages,
    objectCount,
    endObjectCount,
    imageCount,
    creator: readInfo('Creator'),
    producer: readInfo('Producer'),
    creationDate,
    modificationDate,
    metadataInconsistent,
    activeContent,
    structureValid,
    suspiciousStructure,
    extractedText: text,
    extractionAvailable: typeof text === 'string',
    extractionWarnings
  };
}

function normalizeText(value) {
  return String(value || '').normalize('NFKC').toLocaleLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim().replace(/\s+/g, ' ');
}

function findDetectedField(text, name) {
  const labels = {
    studentName: /^(?:student\s+name|full\s+name|name)\s*[:\-]\s*(.+)$/i,
    degree: /^(?:degree|qualification|program(?:me)?)\s*[:\-]\s*(.+)$/i,
    university: /^(?:university|institution|college)\s*[:\-]\s*(.+)$/i,
    graduationYear: /^(?:graduation\s+year|year\s+of\s+graduation|year)\s*[:\-]\s*(.+)$/i,
    credentialId: /^(?:credential\s+id|certificate\s+id|record\s+id)\s*[:\-]\s*(.+)$/i
  };
  const found = String(text || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of found) {
    const match = line.match(labels[name]);
    if (match && match[1].trim()) return match[1].trim().slice(0, 200);
  }
  return null;
}

function compareCredentialFields(text, credential) {
  const fields = [
    ['studentName', 'studentName', credential.studentName],
    ['degree', 'degree', credential.degree],
    ['university', 'university', credential.university],
    ['graduationYear', 'graduationYear', credential.graduationYear],
    ['credentialId', 'credentialId', credential.id]
  ];
  const extractionAvailable = typeof text === 'string' && text.trim().length > 0;
  return Object.fromEntries(fields.map(([key, label, expected]) => {
    const detected = findDetectedField(text, key);
    const normalizedExpected = normalizeText(expected);
    const normalizedDetected = normalizeText(detected);
    const match = extractionAvailable && (normalizedExpected === normalizedDetected || normalizeText(text).includes(normalizedExpected));
    return [key, {
      expected: String(expected),
      detected: detected || (match ? String(expected) : null),
      match,
      extractionAvailable
    }];
  }));
}

function hasEditingMetadata(metadata) {
  return /photoshop|gimp|imagemagick|paint\.net|canva|inkscape|acrobat pro/i.test(metadata || '');
}

function scoreDocument({ fileValid, details, fields, credential, signatureIndicator }) {
  const checks = [];
  const addCheck = (id, label, points, maxPoints, status, evidence) => {
    checks.push({ id, label, points, maxPoints, status, evidence });
  };

  addCheck('file-integrity', 'File integrity and detected type', fileValid ? 15 : 0, 15, fileValid ? 'pass' : 'fail', 'SHA-256 calculated and file signature matched the declared MIME type.');
  const structureValid = details.structureValid;
  addCheck('document-structure', 'Document structure', structureValid ? 20 : 0, 20, structureValid ? 'pass' : 'warning', details.structureEvidence);

  const editorMetadata = hasEditingMetadata(details.metadataText);
  const metadataInconsistent = Boolean(details.metadataInconsistent);
  const metadataPoints = editorMetadata || metadataInconsistent ? 0 : details.metadataAvailable ? 10 : 5;
  const metadataStatus = editorMetadata || metadataInconsistent ? 'warning' : details.metadataAvailable ? 'pass' : 'unavailable';
  addCheck('metadata-consistency', 'Metadata consistency', metadataPoints, 10, metadataStatus, editorMetadata ? 'Editing-software metadata was found; this is an indicator only.' : metadataInconsistent ? 'Modification time precedes creation time.' : 'No inconsistent metadata indicator was detected.');

  const extractionAvailable = typeof details.extractedText === 'string' && details.extractedText.trim().length > 0;
  const extractedNonempty = extractionAvailable;
  addCheck('text-extraction', 'Text extraction', extractedNonempty ? 15 : 0, 15, extractedNonempty ? 'pass' : 'unavailable', extractedNonempty ? `${details.extractedText.length} characters extracted locally.` : 'Text extraction was unavailable or produced no text; no text match is inferred.');

  let matchedFields = 0;
  let mismatchFields = 0;
  if (credential) {
    for (const [name, comparison] of Object.entries(fields)) {
      if (comparison.match) matchedFields += 1;
      else if (comparison.extractionAvailable) mismatchFields += 1;
    }
    const fieldPoints = extractionAvailable ? matchedFields * 5 : 0;
    addCheck('credential-field-match', 'Credential field matching', fieldPoints, 25, !extractionAvailable ? 'unavailable' : mismatchFields ? 'warning' : 'pass', extractionAvailable ? `${matchedFields} of 5 expected fields matched.` : 'Credential fields were not compared because text extraction was unavailable.');
  }

  const lowResolution = Boolean(details.lowResolution);
  const signaturePoints = lowResolution ? 0 : signatureIndicator.status === 'marker_present' ? 15 : signatureIndicator.status === 'unassessed' ? 7 : 0;
  addCheck('signature-indicator', 'Visual/document signature indicator', signaturePoints, 15, lowResolution ? 'warning' : signatureIndicator.status === 'marker_present' ? 'pass' : 'unavailable', lowResolution ? 'Image resolution is too low for reliable document review.' : signatureIndicator.message);

  const possible = checks.reduce((total, check) => total + check.maxPoints, 0);
  const earned = checks.reduce((total, check) => total + check.points, 0);
  const score = possible ? Math.round((earned / possible) * 100) : 0;
  const warnings = [...details.warnings];
  if (mismatchFields > 0) warnings.push(`${mismatchFields} expected credential field(s) did not match extracted document text.`);
  if (!extractionAvailable) warnings.push('Text extraction was unavailable; the analysis did not infer credential field matches.');
  if (editorMetadata) warnings.push('Editing-software metadata was found. This is not proof of document tampering.');
  if (details.activeContent && details.activeContent.length) warnings.push(`Potentially active PDF content detected: ${details.activeContent.join(', ')}.`);

  let classification = score >= 85 ? 'HIGH_CONFIDENCE' : score >= 55 ? 'REVIEW_REQUIRED' : 'SUSPICIOUS';
  if (mismatchFields >= 2 || details.suspiciousStructure || editorMetadata || metadataInconsistent) classification = 'SUSPICIOUS';
  else if (mismatchFields > 0 || !extractionAvailable || lowResolution || signatureIndicator.status !== 'marker_present') classification = 'REVIEW_REQUIRED';

  return {
    score,
    classification,
    checks,
    warnings: [...new Set(warnings)],
    reasons: checks.filter((check) => check.status !== 'pass').map((check) => check.evidence),
    matchedFields,
    mismatchFields,
    metadataText: details.metadataText
  };
}

async function analyzeDocument({ filePath, declaredMimeType, originalName, credential }) {
  const stat = fs.statSync(filePath);
  if (!stat.isFile() || stat.size === 0 || stat.size > MAX_DOCUMENT_BYTES) throw new Error('Invalid document size.');
  const buffer = fs.readFileSync(filePath);
  const detectedType = detectFileType(buffer);
  const declaredExtension = SUPPORTED_TYPES[declaredMimeType];
  const actualExtension = path.extname(String(originalName || '')).toLowerCase();
  if (!detectedType || !declaredExtension || detectedType.mimeType !== declaredMimeType || detectedType.extension !== actualExtension) {
    const error = new Error('The uploaded file content, name, and MIME type must agree.');
    error.code = 'INVALID_DOCUMENT_TYPE';
    throw error;
  }

  const fileHash = crypto.createHash('sha256').update(buffer).digest('hex');
  let details;
  let metadata = {};
  let structureEvidence;
  let extractedText = null;
  let signatureIndicator;
  const warnings = [];

  if (detectedType.mimeType === 'application/pdf') {
    const pdf = await inspectPdf(filePath, buffer);
    extractedText = pdf.extractedText;
    metadata = {
      pages: pdf.pages,
      creator: pdf.creator,
      producer: pdf.producer,
      creationDate: pdf.creationDate,
      modificationDate: pdf.modificationDate,
      activeContent: pdf.activeContent
    };
    structureEvidence = pdf.structureValid ? `${pdf.pages} page(s); ${pdf.objectCount} balanced PDF objects.` : 'PDF header, EOF, object balance, metadata tool, or page count was inconsistent/unavailable.';
    if (pdf.extractionWarnings.length) warnings.push(...pdf.extractionWarnings);
    if (pdf.suspiciousStructure) warnings.push('PDF structure contains unbalanced objects or potentially active content.');
    const markerPresent = Boolean(extractedText && /signature|signed\s+by|registrar|authorized\s+signatory/i.test(extractedText));
    signatureIndicator = markerPresent
      ? { status: 'marker_present', message: 'Signature-related text was found; this does not authenticate a handwritten signature.' }
      : { status: extractedText ? 'marker_absent' : 'unassessed', message: extractedText ? 'No signature-related text marker was found; visual signature authenticity is not assessed.' : 'No text was available to assess a signature marker.' };
    details = {
      structureValid: pdf.structureValid,
      structureEvidence,
      metadataAvailable: Boolean(pdf.creator || pdf.producer || pdf.creationDate || pdf.modificationDate),
      metadataInconsistent: pdf.metadataInconsistent,
      metadataText: `${pdf.creator || ''} ${pdf.producer || ''}`,
      extractedText,
      activeContent: pdf.activeContent,
      suspiciousStructure: pdf.suspiciousStructure,
      warnings
    };
  } else {
    const image = detectedType.mimeType === 'image/png' ? inspectPng(buffer) : inspectJpeg(buffer);
    const metadataText = image.metadata;
    const edited = hasEditingMetadata(metadataText);
    metadata = {
      width: image.width,
      height: image.height,
      exifPresent: Boolean(image.exifPresent),
      crcErrors: image.crcErrors || 0,
      trailingBytes: image.trailingBytes || 0,
      editingSoftwareMetadata: edited
    };
    structureEvidence = image.structureValid
      ? `${image.format} structure is readable; dimensions ${image.width} x ${image.height}.`
      : `${image.format} dimensions, end marker, chunk integrity, or trailing data are inconsistent.`;
    if (edited) warnings.push('Image metadata names editing software; this is an indicator only.');
    if (!image.width || !image.height || image.width < 300 || image.height < 300) warnings.push('Image dimensions are missing or low for a document scan.');
    signatureIndicator = {
      status: 'unassessed',
      message: 'The image is a scan/photo; signature region detection requires OCR/layout analysis and is not inferred.'
    };
    details = {
      structureValid: image.structureValid,
      structureEvidence,
      metadataAvailable: true,
      metadataInconsistent: false,
      metadataText,
      extractedText: null,
      activeContent: [],
      suspiciousStructure: !image.structureValid || Boolean(image.trailingBytes || image.crcErrors),
      lowResolution: !image.width || !image.height || image.width < 300 || image.height < 300,
      warnings
    };
  }

  const fields = credential ? compareCredentialFields(extractedText, credential) : null;
  const scoring = scoreDocument({
    fileValid: true,
    details,
    fields,
    credential,
    signatureIndicator
  });
  const indicators = [
    { id: 'file-type', status: 'pass', message: `${detectedType.mimeType} matches the file signature.` },
    { id: 'document-structure', status: details.structureValid ? 'pass' : 'warning', message: structureEvidence },
    { id: 'text-extraction', status: details.extractedText && details.extractedText.trim() ? 'available' : 'unavailable', message: details.extractedText && details.extractedText.trim() ? 'Local text extraction produced content.' : 'No text was extracted; no text-based conclusion is made.' },
    { id: 'signature-indicator', status: signatureIndicator.status, message: signatureIndicator.message }
  ];
  if (details.metadataText && hasEditingMetadata(details.metadataText)) indicators.push({ id: 'editing-metadata', status: 'warning', message: 'Editing-software metadata detected; it is not proof of tampering.' });
  if (fields) {
    for (const [name, match] of Object.entries(fields)) {
      indicators.push({ id: `field-${name}`, status: match.match ? 'match' : match.extractionAvailable ? 'mismatch' : 'unavailable', message: match.match ? `${name} matched.` : match.extractionAvailable ? `${name} did not match.` : `${name} was not compared because extraction was unavailable.` });
    }
  }

  return {
    fileHash,
    fileType: detectedType.mimeType,
    fileSizeBytes: stat.size,
    metadata,
    textExtraction: {
      available: Boolean(extractedText && extractedText.trim()),
      method: detectedType.mimeType === 'application/pdf' ? 'local pdftotext' : 'not available for raster images',
      characterCount: extractedText ? extractedText.length : 0
    },
    fieldMatches: fields,
    signatureIndicator,
    score: scoring.score,
    classification: scoring.classification,
    indicators,
    warnings: scoring.warnings,
    checks: scoring.checks,
    reasons: scoring.reasons,
    scoring: {
      formula: 'Weighted points earned / applicable points × 100; mismatch, unavailable extraction, structure and metadata indicators reduce points. Crypto checks are reported separately and do not change this score.',
      earnedPoints: scoring.checks.reduce((total, check) => total + check.points, 0),
      applicablePoints: scoring.checks.reduce((total, check) => total + check.maxPoints, 0)
    }
  };
}

async function verifyCryptographicEvidence(credential, vcRecord, issuerIdentity, studentIdentity) {
  if (!credential) {
    return {
      vcSignature: { checked: false, valid: null, result: 'NOT_AVAILABLE' },
      credentialBinding: { checked: false, valid: null, result: 'NOT_AVAILABLE' },
      blockchainProof: { checked: false, exists: false, result: 'NOT_AVAILABLE' },
      credentialStatus: null
    };
  }

  let signatureValid = false;
  let bindingValid = false;
  if (vcRecord) {
    signatureValid = verifyCredentialVC(vcRecord.vc, vcRecord.issuerPublicKey);
    bindingValid = verifyCredentialBinding(
      vcRecord.vc,
      credential,
      vcRecord,
      issuerIdentity,
      studentIdentity
    );
  }
  const blockchain = await checkBlockchainValidity({ id: credential.id, hash: credential.hash });
  return {
    vcSignature: { checked: Boolean(vcRecord), valid: vcRecord ? signatureValid : null, result: vcRecord ? signatureValid ? 'VALID' : 'VC_SIGNATURE_INVALID' : 'NOT_AVAILABLE' },
    credentialBinding: { checked: Boolean(vcRecord), valid: vcRecord ? bindingValid : null, result: vcRecord ? bindingValid ? 'VALID' : 'MISMATCH' : 'NOT_AVAILABLE' },
    blockchainProof: {
      checked: true,
      exists: Boolean(blockchain.exists),
      matchesHash: Boolean(blockchain.matchesHash),
      issuer: blockchain.issuer || null,
      result: blockchain.result
    },
    credentialStatus: credential.status
  };
}

module.exports = {
  MAX_DOCUMENT_BYTES,
  MAX_TEXT_BYTES,
  UPLOAD_DIRECTORY,
  SUPPORTED_TYPES,
  ensureUploadDirectory,
  createUploadFilename,
  detectFileType,
  inspectPng,
  inspectJpeg,
  normalizeText,
  compareCredentialFields,
  scoreDocument,
  analyzeDocument,
  verifyCryptographicEvidence
};