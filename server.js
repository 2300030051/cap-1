const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const QRCode = require('qrcode');
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const bcrypt = require('bcryptjs');
const multer = require('multer');
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 12);

const {
  db,
  saveIssuedCredential,
  getAllCredentials,
  getCredentialById,
  revokeCredential,
  setCredentialBlockchainMetadata,
  getCredentialByHash,
  getStudentIdentityByWalletId,
  getStudentIdentityByDid,
  getIssuerIdentityByDid,
  setIssuerIdentity,
  getWalletCredentials,
  getVerifiableCredentialByCredentialId,
  getVerifiableCredentialById,
  createAiAnalysisResult,
  getAiAnalysisById,
  getAiAnalysesByCredentialId,
  getUserByUsername,
  createInitialIssuer,
  createVerificationLog,
  getDashboardStats,
  getRecentVerifications
} = require('./database');
const {
  loadOrCreateIdentity,
  getIdentity,
  createIdentity,
  persistIdentity
} = require('./didService');
const {
  createCredentialVC,
  signCredentialVC,
  verifyCredentialVC,
  verifyCredentialBinding
} = require('./verifiableCredentialService');
const {
  anchorCredential,
  revokeCredentialOnChain,
  checkBlockchainValidity
} = require('./blockchainService');
const {
  MAX_DOCUMENT_BYTES,
  SUPPORTED_TYPES,
  ensureUploadDirectory,
  createUploadFilename,
  analyzeDocument,
  verifyCryptographicEvidence
} = require('./aiAuthenticityService');

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS || 0);

const documentUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, callback) => {
      try {
        callback(null, ensureUploadDirectory());
      } catch (error) {
        callback(error);
      }
    },
    filename: (req, file, callback) => {
      try {
        callback(null, createUploadFilename(file.mimetype));
      } catch (error) {
        callback(error);
      }
    }
  }),
  limits: {
    fileSize: MAX_DOCUMENT_BYTES,
    files: 1,
    fields: 4,
    fieldSize: 4096,
    parts: 5
  },
  fileFilter: (req, file, callback) => {
    if (!SUPPORTED_TYPES[file.mimetype]) {
      const error = new Error('Unsupported document type. Upload a PDF, PNG, or JPG/JPEG file.');
      error.code = 'UNSUPPORTED_DOCUMENT_TYPE';
      return callback(error);
    }
    callback(null, true);
  }
});

if (!SESSION_SECRET) {
  throw new Error('SESSION_SECRET must be set before starting the server.');
}

if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0) {
  throw new Error('TRUST_PROXY_HOPS must be a non-negative integer.');
}

if (trustProxyHops > 0) {
  app.set('trust proxy', trustProxyHops);
}

async function initializeIssuerAccount() {
  const username = process.env.ISSUER_USERNAME;
  const password = process.env.ISSUER_PASSWORD;

  if (!username || !password) {
    console.warn('ISSUER_USERNAME and ISSUER_PASSWORD are not both set; no initial issuer account was created.');
    return;
  }

  const issuerIdentity = loadOrCreateIdentity('issuer', username);

  if (getUserByUsername(username)) {
    setIssuerIdentity(username, issuerIdentity.did, issuerIdentity.publicKey);
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  createInitialIssuer({
    id: crypto.randomUUID(),
    username,
    passwordHash,
    createdAt: new Date().toISOString(),
    issuerDid: issuerIdentity.did,
    issuerPublicKey: issuerIdentity.publicKey
  });
}

const issuerInitialization = initializeIssuerAccount().catch((error) => {
  console.error('Failed to initialize issuer account:', error);
  process.exit(1);
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '64kb' }));
app.use(session({
  name: 'credential.sid',
  store: new SqliteStore({
    client: db,
    expired: {
      clear: true,
      intervalMs: 15 * 60 * 1000
    }
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// --------------------------------------------------
// Helpers
// --------------------------------------------------

function generateHash(record) {
  const str =
    `${record.studentName}|` +
    `${record.degree}|` +
    `${record.university}|` +
    `${record.graduationYear}|` +
    `${record.issuedAt}`;

  return crypto
    .createHash('sha256')
    .update(str)
    .digest('hex');
}

function getPublicOrigin(req) {
  const configuredOrigin = process.env.PUBLIC_ORIGIN || `${req.protocol}://${req.get('host')}`;
  const origin = new URL(configuredOrigin);

  if (origin.protocol !== 'http:' && origin.protocol !== 'https:') {
    throw new Error('PUBLIC_ORIGIN must use HTTP or HTTPS.');
  }

  return origin.origin;
}

function prepareStudentWallet(studentName, preferredWalletId) {
  const safeName = typeof studentName === 'string' && studentName.trim()
    ? studentName.trim()
    : 'demo-student';

  const walletName = preferredWalletId && String(preferredWalletId).trim()
    ? String(preferredWalletId).trim()
    : safeName;

  const existingRecord = getStudentIdentityByWalletId(walletName);
  if (existingRecord) {
    return {
      identity: getIdentity('student', walletName),
      wallet: existingRecord,
      needsPersistence: false
    };
  }

  const identity = getIdentity('student', walletName) || createIdentity('student', walletName);
  const record = getStudentIdentityByDid(identity.did);

  if (record) {
    return {
      identity,
      wallet: record,
      needsPersistence: false
    };
  }

  return {
    identity,
    wallet: {
      id: crypto.randomUUID(),
      walletId: walletName,
      studentName: safeName,
      did: identity.did,
      publicKey: identity.publicKey,
      createdAt: new Date().toISOString()
    },
    needsPersistence: true
  };
}

function createAndStoreVerifiableCredential({ credentialRecord, studentName, walletId, resolvedStudentWallet }) {
  const issuerIdentity = loadOrCreateIdentity('issuer', process.env.ISSUER_USERNAME || 'issuer');
  const studentWallet = resolvedStudentWallet || ensureStudentWallet(studentName || walletId || 'demo-student', walletId || studentName || 'demo-student');

  const vcPayload = createCredentialVC({
    credential: {
      id: credentialRecord.id,
      studentName: credentialRecord.studentName,
      degree: credentialRecord.degree,
      university: credentialRecord.university,
      graduationYear: credentialRecord.graduationYear,
      issuedAt: credentialRecord.issuedAt,
      status: credentialRecord.status
    },
    issuerDid: issuerIdentity.did,
    studentDid: studentWallet.wallet.did
  });

  const signedVc = signCredentialVC(vcPayload, issuerIdentity);

  return {
    vc: signedVc.vc,
    signature: signedVc.signature,
    walletId: studentWallet.wallet.walletId,
    studentDid: studentWallet.wallet.did,
    issuerDid: issuerIdentity.did,
    issuerPublicKey: issuerIdentity.publicKey
  };
}

// --------------------------------------------------
// Routes
// --------------------------------------------------

function requireIssuer(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'ISSUER') {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  next();
}

function receiveDocumentUpload(req, res, next) {
  documentUpload.single('document')(req, res, (error) => {
    if (!error) return next();

    const status = error.code === 'UNSUPPORTED_DOCUMENT_TYPE'
      ? 415
      : error.code === 'LIMIT_FILE_SIZE'
        ? 413
        : error instanceof multer.MulterError
          ? 400
          : 500;
    const message = status === 415
      ? 'Unsupported document type. Upload a PDF, PNG, or JPG/JPEG file.'
      : status === 413
        ? 'Document exceeds the 10 MB upload limit.'
        : status === 400
          ? 'Invalid document upload request.'
          : 'Unable to receive the document.';
    res.status(status).json({ error: message });
  });
}

function requireIssuerPage(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'ISSUER') {
    return res.redirect('/login.html');
  }

  next();
}

// --------------------------------------------------
// Pages
// --------------------------------------------------

app.get('/', requireIssuerPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/index.html', requireIssuerPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/verify.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'verify.html'));
});

app.get('/wallet.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'wallet.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/styles.css', (req, res) => {
  res.type('text/css').sendFile(path.join(__dirname, 'styles.css'));
});

// --------------------------------------------------
// Issuer authentication
// --------------------------------------------------

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== 'string' || typeof password !== 'string' ||
    Buffer.byteLength(username, 'utf8') > 256 || Buffer.byteLength(password, 'utf8') > 1024
  ) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  try {
    const user = getUserByUsername(username);
    const passwordMatches = user
      ? await bcrypt.compare(password, user.password_hash)
      : await bcrypt.compare(password, DUMMY_PASSWORD_HASH);

    if (!user || !passwordMatches) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    req.session.regenerate((error) => {
      if (error) {
        console.error('Failed to start issuer session:', error);
        return res.status(500).json({ error: 'Unable to start session.' });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      req.session.save((saveError) => {
        if (saveError) {
          console.error('Failed to save issuer session:', saveError);
          return res.status(500).json({ error: 'Unable to start session.' });
        }

        res.json({ authenticated: true, username: user.username, role: user.role });
      });
    });
  } catch (error) {
    console.error('Issuer login failed:', error);
    res.status(500).json({ error: 'Unable to log in right now.' });
  }
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) {
    return res.json({ authenticated: false });
  }

  res.json({
    authenticated: true,
    username: req.session.user.username,
    role: req.session.user.role
  });
});

app.post('/api/auth/logout', (req, res) => {
  if (!req.session) {
    res.clearCookie('credential.sid', { httpOnly: true, sameSite: 'lax' });
    return res.json({ authenticated: false });
  }

  req.session.destroy((error) => {
    if (error) {
      console.error('Failed to end issuer session:', error);
      return res.status(500).json({ error: 'Unable to log out right now.' });
    }

    res.clearCookie('credential.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    res.json({ authenticated: false });
  });
});

// --------------------------------------------------
// Local academic document analysis
// --------------------------------------------------

app.post('/api/ai/analyze-document', requireIssuer, receiveDocumentUpload, async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Upload a document in the "document" field.' });
  }

  try {
    await require('fs').promises.chmod(req.file.path, 0o600);

    const requestedCredentialId = req.body && req.body.credentialId;
    if (requestedCredentialId !== undefined && typeof requestedCredentialId !== 'string') {
      return res.status(400).json({ error: 'credentialId must be a string.' });
    }

    const credentialId = requestedCredentialId && requestedCredentialId.trim()
      ? requestedCredentialId.trim()
      : null;
    const credential = credentialId ? getCredentialById(credentialId) : null;
    if (credentialId && !credential) {
      return res.status(404).json({ error: 'Credential not found.' });
    }

    const documentResult = await analyzeDocument({
      filePath: req.file.path,
      declaredMimeType: req.file.mimetype,
      originalName: req.file.originalname,
      credential
    });
    const vcRecord = credential ? getVerifiableCredentialByCredentialId(credential.id) : null;
    const issuerIdentity = vcRecord ? getIssuerIdentityByDid(vcRecord.issuerDid) : null;
    const studentIdentity = vcRecord ? getStudentIdentityByDid(vcRecord.studentDid) : null;
    const cryptographicVerification = await verifyCryptographicEvidence(
      credential,
      vcRecord,
      issuerIdentity,
      studentIdentity
    );
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const analysis = {
      id,
      credentialId,
      createdAt,
      fileHash: documentResult.fileHash,
      fileType: documentResult.fileType,
      fileSizeBytes: documentResult.fileSizeBytes,
      score: documentResult.score,
      classification: documentResult.classification,
      indicators: documentResult.indicators,
      warnings: documentResult.warnings,
      checks: documentResult.checks,
      documentAnalysis: {
        fileHash: documentResult.fileHash,
        fileType: documentResult.fileType,
        fileSizeBytes: documentResult.fileSizeBytes,
        metadata: documentResult.metadata,
        textExtraction: documentResult.textExtraction,
        fieldMatches: documentResult.fieldMatches,
        signatureIndicator: documentResult.signatureIndicator,
        indicators: documentResult.indicators,
        warnings: documentResult.warnings,
        checks: documentResult.checks,
        scoring: documentResult.scoring,
        reasons: documentResult.reasons
      },
      cryptographicVerification,
      finalAssessment: {
        score: documentResult.score,
        classification: documentResult.classification,
        reasons: documentResult.reasons,
        warnings: documentResult.warnings,
        disclaimer: 'AI authenticity analysis provides risk indicators and an explainable confidence assessment; it does not mathematically prove that a physical academic document is genuine.'
      }
    };

    createAiAnalysisResult({
      id,
      credentialId,
      fileHash: documentResult.fileHash,
      fileType: documentResult.fileType,
      score: documentResult.score,
      classification: documentResult.classification,
      analysis,
      createdAt
    });

    res.status(201).json(analysis);
  } catch (error) {
    if (error.code === 'INVALID_DOCUMENT_TYPE') {
      return res.status(415).json({ error: 'The uploaded file content, name, and MIME type must agree.' });
    }
    console.error('Academic document analysis failed.');
    res.status(422).json({ error: 'The document could not be analyzed.' });
  } finally {
    await require('fs').promises.unlink(req.file.path).catch(() => {});
  }
});

app.get('/api/ai/analysis/:id', requireIssuer, (req, res) => {
  try {
    const analysis = getAiAnalysisById(req.params.id);
    if (!analysis) return res.status(404).json({ error: 'Analysis not found.' });
    res.json(analysis);
  } catch (error) {
    console.error('Error retrieving AI analysis:', error.message);
    res.status(500).json({ error: 'Unable to retrieve analysis.' });
  }
});

app.get('/api/credentials/:id/ai-analysis', requireIssuer, (req, res) => {
  try {
    if (!getCredentialById(req.params.id)) {
      return res.status(404).json({ error: 'Credential not found.' });
    }
    res.json(getAiAnalysesByCredentialId(req.params.id));
  } catch (error) {
    console.error('Error retrieving credential AI history:', error.message);
    res.status(500).json({ error: 'Unable to retrieve analysis history.' });
  }
});

// --------------------------------------------------
// Issue a new credential
// --------------------------------------------------

app.post('/api/credentials', requireIssuer, async (req, res) => {
  try {
    const {
      studentName,
      degree,
      university,
      graduationYear
    } = req.body || {};

    if ([studentName, degree, university].some((value) => typeof value !== 'string')) {
      return res.status(400).json({
        error: 'Student name, degree, and university must be text.'
      });
    }

    const normalizedStudentName = studentName.trim();
    const normalizedDegree = degree.trim();
    const normalizedUniversity = university.trim();
    const parsedGraduationYear = Number(graduationYear);
    if (
      !normalizedStudentName || normalizedStudentName.length > 200 ||
      !normalizedDegree || normalizedDegree.length > 200 ||
      !normalizedUniversity || normalizedUniversity.length > 200 ||
      !Number.isInteger(parsedGraduationYear) || parsedGraduationYear < 1000 || parsedGraduationYear > 9999
    ) {
      return res.status(400).json({
        error: 'Provide non-empty student, degree, and university values up to 200 characters and a four-digit graduation year.'
      });
    }

    const record = {
      id: crypto.randomUUID(),
      studentName: normalizedStudentName,
      degree: normalizedDegree,
      university: normalizedUniversity,
      graduationYear: parsedGraduationYear,
      issuedAt: new Date().toISOString()
    };

    record.hash = generateHash(record);

    try {
      const wallet = prepareStudentWallet(normalizedStudentName, `wallet:${normalizedStudentName}`);
      const vcData = createAndStoreVerifiableCredential({
        credentialRecord: record,
        studentName: normalizedStudentName,
        walletId: wallet.wallet.walletId,
        resolvedStudentWallet: wallet
      });

      const vcRecord = {
        id: crypto.randomUUID(),
        credentialId: record.id,
        walletId: vcData.walletId,
        issuerDid: vcData.issuerDid,
        studentDid: vcData.studentDid,
        issuerPublicKey: vcData.issuerPublicKey,
        vcPayload: vcData.vc,
        signature: vcData.signature,
        createdAt: new Date().toISOString()
      };

      const blockchainResult = await anchorCredential({
        id: record.id,
        hash: record.hash
      });

      if (wallet.needsPersistence) {
        persistIdentity(wallet.identity);
      }

      const updatedCredential = saveIssuedCredential(
        record,
        blockchainResult,
        vcRecord,
        wallet.needsPersistence ? wallet.wallet : null
      );

      const enrichedCredential = {
        ...updatedCredential,
        verifiableCredential: {
          ...vcRecord,
          vc: vcData.vc
        }
      };

      res.status(201).json(enrichedCredential);
    } catch (error) {
      console.error('Credential issuance failed:', error);
      return res.status(502).json({
        error: 'Credential issuance failed. Verify blockchain availability and retry.'
      });
    }
  } catch (error) {
    console.error('Error issuing credential:', error);

    res.status(500).json({
      error: 'Failed to issue credential.'
    });
  }
});

app.post('/api/wallet/create', (req, res) => {
  try {
    const { studentName, walletId } = req.body || {};
    if (
      (walletId !== undefined && (typeof walletId !== 'string' || walletId.length > 200)) ||
      (studentName !== undefined && (typeof studentName !== 'string' || studentName.length > 200))
    ) {
      return res.status(400).json({ error: 'Wallet ID and student name must be text up to 200 characters.' });
    }
    const requestedWalletId = walletId && walletId.trim()
      ? walletId.trim()
      : studentName && studentName.trim()
        ? `wallet:${studentName.trim()}`
        : null;
    const wallet = requestedWalletId
      ? getStudentIdentityByWalletId(requestedWalletId) || getStudentIdentityByDid(requestedWalletId)
      : null;
    if (!wallet) return res.status(404).json({ error: 'Wallet not found.' });

    res.json({
      walletId: wallet.walletId,
      did: wallet.did,
      studentName: wallet.studentName,
      status: 'ACTIVE'
    });
  } catch (error) {
    console.error('Error creating wallet:', error);
    res.status(500).json({ error: 'Failed to create wallet.' });
  }
});

app.get('/api/wallet/me', (req, res) => {
  try {
    const requestedWalletId = req.query.walletId || (
      req.query.studentName ? `wallet:${req.query.studentName}` : null
    );
    if (typeof requestedWalletId !== 'string' || requestedWalletId.length > 200) {
      return res.status(400).json({ error: 'A valid wallet ID is required.' });
    }
    const wallet = getStudentIdentityByWalletId(requestedWalletId) || getStudentIdentityByDid(requestedWalletId);
    if (!wallet) return res.status(404).json({ error: 'Wallet not found.' });

    res.json({
      walletId: wallet.walletId,
      did: wallet.did,
      status: 'ACTIVE',
      studentName: wallet.studentName
    });
  } catch (error) {
    console.error('Error retrieving wallet:', error);
    res.status(500).json({ error: 'Failed to load wallet.' });
  }
});

app.get('/api/wallet/credentials', (req, res) => {
  try {
    const walletId = req.query.walletId || 'default-wallet';
    const wallet = getStudentIdentityByWalletId(String(walletId)) || getStudentIdentityByDid(String(walletId));

    if (!wallet) {
      return res.status(404).json({ error: 'Wallet not found.' });
    }

    const credentials = getWalletCredentials(wallet.walletId);
    res.json(credentials);
  } catch (error) {
    console.error('Error retrieving wallet credentials:', error);
    res.status(500).json({ error: 'Failed to load wallet credentials.' });
  }
});

app.get('/api/wallet/credentials/:id', (req, res) => {
  try {
    const record = getVerifiableCredentialById(req.params.id);

    if (!record) {
      return res.status(404).json({ error: 'Credential not found in wallet.' });
    }

    res.json(record);
  } catch (error) {
    console.error('Error retrieving wallet credential:', error);
    res.status(500).json({ error: 'Failed to retrieve wallet credential.' });
  }
});

app.get('/api/wallet/credentials/:id/export', (req, res) => {
  try {
    const record = getVerifiableCredentialById(req.params.id);

    if (!record) {
      return res.status(404).json({ error: 'Credential not found in wallet.' });
    }

    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(record.vc, null, 2));
  } catch (error) {
    console.error('Error exporting wallet credential:', error);
    res.status(500).json({ error: 'Failed to export wallet credential.' });
  }
});

// --------------------------------------------------
// List all credentials
// --------------------------------------------------

app.get('/api/credentials', requireIssuer, (req, res) => {
  try {
    const credentials = getAllCredentials();

    res.json(credentials);

  } catch (error) {
    console.error('Error retrieving credentials:', error);

    res.status(500).json({
      error: 'Failed to retrieve credentials.'
    });
  }
});

// --------------------------------------------------
// Retrieve a credential by ID
// --------------------------------------------------

app.get('/api/credentials/:id', (req, res) => {
  try {
    const credential = getCredentialById(req.params.id);

    if (!credential) {
      return res.status(404).json({
        error: 'Credential not found.'
      });
    }

    res.json(credential);
  } catch (error) {
    console.error('Error retrieving credential:', error);

    res.status(500).json({
      error: 'Failed to retrieve credential.'
    });
  }
});

// --------------------------------------------------
// Generate a QR code for a credential verification URL
// --------------------------------------------------

app.get('/api/credentials/:id/qr', async (req, res) => {
  try {
    const credential = getCredentialById(req.params.id);

    if (!credential) {
      return res.status(404).json({
        error: 'Credential not found.'
      });
    }

    const verificationUrl = new URL('/verify.html', getPublicOrigin(req));
    verificationUrl.searchParams.set('id', credential.id);

    const image = await QRCode.toBuffer(verificationUrl.toString(), {
      type: 'png',
      width: 220,
      margin: 1,
      errorCorrectionLevel: 'M'
    });

    res.type('png').send(image);
  } catch (error) {
    console.error('Error generating credential QR code:', error);

    res.status(500).json({
      error: 'Failed to generate credential QR code.'
    });
  }
});

// --------------------------------------------------
// Revoke a credential
// --------------------------------------------------

app.patch('/api/credentials/:id/revoke', requireIssuer, async (req, res) => {
  try {
    const existingCredential = getCredentialById(req.params.id);

    if (!existingCredential) {
      return res.status(404).json({
        error: 'Credential not found.'
      });
    }

    try {
      const blockchainResult = await revokeCredentialOnChain({
        id: req.params.id
      });

      const updatedCredential = setCredentialBlockchainMetadata(
        req.params.id,
        blockchainResult.transactionHash,
        blockchainResult.status
      );

      const revokedCredential = revokeCredential(req.params.id);

      res.json(revokedCredential);
    } catch (error) {
      console.error('Blockchain revocation failed:', error);
      return res.status(502).json({
        error: 'Blockchain revocation failed. SQLite status was not changed to REVOKED.',
        credential: existingCredential,
        result: 'BLOCKCHAIN_VERIFICATION_FAILED'
      });
    }
  } catch (error) {
    console.error('Error revoking credential:', error);

    res.status(500).json({
      error: 'Failed to revoke credential.'
    });
  }
});

// --------------------------------------------------
// Verify a credential using its hash
// --------------------------------------------------

app.get('/api/verify/:hash', async (req, res) => {
  try {
    const credential = getCredentialByHash(req.params.hash);

    if (!credential) {
      try {
        createVerificationLog('UNKNOWN', 'NOT_FOUND');
      } catch (logError) {
        console.error('Error logging missing credential verification:', logError);
      }

      return res.status(404).json({
        valid: false,
        result: 'NOT_FOUND',
        message: 'No matching credential found.'
      });
    }

    const recomputedHash = generateHash(credential);
    const integrityValid = recomputedHash === credential.hash;

    let blockchainStatus = {
      exists: false,
      result: 'BLOCKCHAIN_VERIFICATION_FAILED',
      message: 'Blockchain verification is unavailable.'
    };

    const vcRecord = credential ? getVerifiableCredentialByCredentialId(credential.id) : null;
    let vcVerification = null;

    if (vcRecord) {
      const signatureValid = verifyCredentialVC(vcRecord.vc, vcRecord.issuerPublicKey);
      const issuerIdentity = getIssuerIdentityByDid(vcRecord.issuerDid);
      const studentIdentity = getStudentIdentityByDid(vcRecord.studentDid);
      const credentialBindingValid = verifyCredentialBinding(
        vcRecord.vc,
        credential,
        vcRecord,
        issuerIdentity,
        studentIdentity
      );

      vcVerification = {
        valid: signatureValid && credentialBindingValid,
        signatureValid,
        credentialBindingValid,
        issuerDid: vcRecord.issuerDid,
        studentDid: vcRecord.studentDid,
        result: signatureValid && credentialBindingValid ? 'VALID' : 'VC_SIGNATURE_INVALID'
      };
    }

    if (integrityValid) {
      blockchainStatus = await checkBlockchainValidity({
        id: credential.id,
        hash: credential.hash
      });
    }

    let result = 'INVALID';
    if (!integrityValid) {
      result = 'INVALID';
    } else if (credential.status === 'REVOKED' || blockchainStatus.revoked) {
      result = 'REVOKED';
    } else if (vcVerification && !vcVerification.valid) {
      result = 'VC_SIGNATURE_INVALID';
    } else if (blockchainStatus.result === 'BLOCKCHAIN_VERIFICATION_FAILED') {
      result = 'BLOCKCHAIN_VERIFICATION_FAILED';
    } else if (blockchainStatus.result === 'VALID') {
      result = 'VALID';
    } else if (blockchainStatus.result === 'INVALID') {
      result = 'INVALID';
    }

    const valid = result === 'VALID';
    createVerificationLog(credential.id, result);

    res.json({
      valid,
      integrityValid,
      result,
      status: credential.status,
      blockchain: blockchainStatus,
      vc: vcVerification,
      credential
    });
  } catch (error) {
    console.error('Error verifying credential:', error);

    res.status(500).json({
      valid: false,
      result: 'BLOCKCHAIN_VERIFICATION_FAILED',
      error: 'Failed to verify credential.'
    });
  }
});

// --------------------------------------------------
// Dashboard statistics
// --------------------------------------------------

app.get('/api/dashboard/stats', requireIssuer, (req, res) => {
  try {
    res.json(getDashboardStats());
  } catch (error) {
    console.error('Error retrieving dashboard statistics:', error);

    res.status(500).json({
      error: 'Failed to retrieve dashboard statistics.'
    });
  }
});

// --------------------------------------------------
// Recent verification activity
// --------------------------------------------------

app.get('/api/verifications/recent', requireIssuer, (req, res) => {
  try {
    res.json(getRecentVerifications());
  } catch (error) {
    console.error('Error retrieving recent verifications:', error);

    res.status(500).json({
      error: 'Failed to retrieve recent verification activity.'
    });
  }
});

// --------------------------------------------------
// Health check
// --------------------------------------------------

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'Credential Verification Server is running'
  });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  const status = error.type === 'entity.parse.failed'
    ? 400
    : error.type === 'entity.too.large'
      ? 413
      : 500;
  res.status(status).json({
    error: status === 400
      ? 'Malformed JSON request.'
      : status === 413
        ? 'Request body exceeds the allowed size.'
        : 'The request could not be completed.'
  });
});

// --------------------------------------------------
// Start Server
// --------------------------------------------------

issuerInitialization.then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
});