const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const DB_FILE = process.env.CREDENTIAL_DATABASE_FILE || path.join(__dirname, 'credentials.db');

const db = new Database(DB_FILE);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create credentials table
db.exec(`
  CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    student_name TEXT NOT NULL,
    degree TEXT NOT NULL,
    university TEXT NOT NULL,
    graduation_year INTEGER NOT NULL,
    issued_at TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'VALID',
    blockchain_tx_hash TEXT,
    blockchain_status TEXT NOT NULL DEFAULT 'NOT_ANCHORED'
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS student_identities (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL UNIQUE,
    student_name TEXT NOT NULL,
    did TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS verifiable_credentials (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    wallet_id TEXT NOT NULL,
    issuer_did TEXT NOT NULL,
    student_did TEXT NOT NULL,
    issuer_public_key TEXT NOT NULL,
    vc_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS ai_analysis_results (
    id TEXT PRIMARY KEY,
    credential_id TEXT,
    file_hash TEXT NOT NULL,
    file_type TEXT NOT NULL,
    score INTEGER NOT NULL,
    classification TEXT NOT NULL,
    analysis_json TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS verification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    result TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'ISSUER',
    created_at TEXT NOT NULL,
    issuer_did TEXT,
    issuer_public_key TEXT
  )
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_verification_logs_verified_at
  ON verification_logs(verified_at DESC)
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_ai_analysis_credential_created
  ON ai_analysis_results(credential_id, created_at DESC)
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_vc_credential_created
  ON verifiable_credentials(credential_id, created_at DESC)
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_vc_wallet_created
  ON verifiable_credentials(wallet_id, created_at DESC)
`);

function ensureDatabaseSchema() {
  const columns = db.prepare('PRAGMA table_info(credentials)').all();
  const availableColumns = new Set(columns.map((column) => column.name));
  const userColumns = db.prepare('PRAGMA table_info(users)').all();
  const availableUserColumns = new Set(userColumns.map((column) => column.name));

  if (!availableColumns.has('blockchain_tx_hash')) {
    db.exec('ALTER TABLE credentials ADD COLUMN blockchain_tx_hash TEXT');
  }

  if (!availableColumns.has('blockchain_status')) {
    db.exec("ALTER TABLE credentials ADD COLUMN blockchain_status TEXT NOT NULL DEFAULT 'NOT_ANCHORED'");
  }

  if (!availableUserColumns.has('issuer_did')) {
    db.exec('ALTER TABLE users ADD COLUMN issuer_did TEXT');
  }

  if (!availableUserColumns.has('issuer_public_key')) {
    db.exec('ALTER TABLE users ADD COLUMN issuer_public_key TEXT');
  }
}

ensureDatabaseSchema();

// --------------------------------------------------
// Migrate existing credentials.json
// --------------------------------------------------

function migrateFromJSON() {
  const JSON_FILE = path.join(__dirname, 'credentials.json');

  if (!fs.existsSync(JSON_FILE)) {
    return;
  }

  try {
    const data = fs.readFileSync(JSON_FILE, 'utf-8');
    const credentials = JSON.parse(data || '[]');

    if (!Array.isArray(credentials) || credentials.length === 0) {
      return;
    }

    const count = db
      .prepare('SELECT COUNT(*) AS count FROM credentials')
      .get();

    // Only migrate if database is empty
    if (count.count === 0) {
      const insert = db.prepare(`
        INSERT OR IGNORE INTO credentials (
          id,
          student_name,
          degree,
          university,
          graduation_year,
          issued_at,
          hash,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const migrate = db.transaction((records) => {
        for (const record of records) {
          insert.run(
            record.id,
            record.studentName,
            record.degree,
            record.university,
            Number(record.graduationYear),
            record.issuedAt,
            record.hash,
            'VALID'
          );
        }
      });

      migrate(credentials);

      console.log(
        `Migrated ${credentials.length} credential(s) from credentials.json`
      );
    }
  } catch (error) {
    console.error('Migration error:', error);
  }
}

migrateFromJSON();

// --------------------------------------------------
// Database functions
// --------------------------------------------------

function createCredential(record) {
  const stmt = db.prepare(`
    INSERT INTO credentials (
      id,
      student_name,
      degree,
      university,
      graduation_year,
      issued_at,
      hash,
      status,
      blockchain_tx_hash,
      blockchain_status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    record.id,
    record.studentName,
    record.degree,
    record.university,
    Number(record.graduationYear),
    record.issuedAt,
    record.hash,
    'VALID',
    null,
    'NOT_ANCHORED'
  );

  return getCredentialById(record.id);
}

function saveIssuedCredential(record, blockchainMetadata, vcRecord, studentIdentity) {
  const save = db.transaction(() => {
    if (studentIdentity) {
      createStudentIdentity(studentIdentity);
    }
    const savedCredential = createCredential(record);
    setCredentialBlockchainMetadata(
      record.id,
      blockchainMetadata.transactionHash,
      blockchainMetadata.status
    );
    createVerifiableCredentialRecord(vcRecord);
    return getCredentialById(savedCredential.id);
  });

  return save();
}

function getAllCredentials() {
  const rows = db.prepare(`
    SELECT
      id,
      student_name,
      degree,
      university,
      graduation_year,
      issued_at,
      hash,
      status,
      blockchain_tx_hash,
      blockchain_status
    FROM credentials
    ORDER BY rowid DESC
  `).all();

  return rows.map(formatCredential);
}

function getCredentialById(id) {
  const row = db.prepare(`
    SELECT
      id,
      student_name,
      degree,
      university,
      graduation_year,
      issued_at,
      hash,
      status,
      blockchain_tx_hash,
      blockchain_status
    FROM credentials
    WHERE id = ?
  `).get(id);

  return row ? formatCredential(row) : null;
}

function revokeCredential(id) {
  db.prepare(`
    UPDATE credentials
    SET status = 'REVOKED'
    WHERE id = ?
  `).run(id);

  return getCredentialById(id);
}

function deleteCredentialById(id) {
  db.prepare(`
    DELETE FROM credentials
    WHERE id = ?
  `).run(id);
}

function setCredentialBlockchainMetadata(id, txHash, blockchainStatus) {
  db.prepare(`
    UPDATE credentials
    SET blockchain_tx_hash = ?,
        blockchain_status = ?
    WHERE id = ?
  `).run(txHash, blockchainStatus, id);

  return getCredentialById(id);
}

function getCredentialByHash(hash) {
  const row = db.prepare(`
    SELECT
      id,
      student_name,
      degree,
      university,
      graduation_year,
      issued_at,
      hash,
      status,
      blockchain_tx_hash,
      blockchain_status
    FROM credentials
    WHERE hash = ?
  `).get(hash);

  return row ? formatCredential(row) : null;
}

function getUserByUsername(username) {
  return db.prepare(`
    SELECT id, username, password_hash, role, created_at, issuer_did, issuer_public_key
    FROM users
    WHERE username = ?
  `).get(username) || null;
}

function getIssuerIdentityByDid(did) {
  return db.prepare(`
    SELECT issuer_did AS did, issuer_public_key AS publicKey
    FROM users
    WHERE issuer_did = ?
  `).get(did) || null;
}

function createInitialIssuer(user) {
  db.prepare(`
    INSERT OR IGNORE INTO users (id, username, password_hash, role, created_at, issuer_did, issuer_public_key)
    VALUES (?, ?, ?, 'ISSUER', ?, ?, ?)
  `).run(user.id, user.username, user.passwordHash, user.createdAt, user.issuerDid || null, user.issuerPublicKey || null);
}

function setIssuerIdentity(username, did, publicKey) {
  db.prepare(`
    UPDATE users
    SET issuer_did = ?, issuer_public_key = ?
    WHERE username = ?
  `).run(did, publicKey, username);
}

function createStudentIdentity(record) {
  const existing = db.prepare(`
    SELECT * FROM student_identities WHERE did = ? OR wallet_id = ?
  `).get(record.did, record.walletId);

  if (existing) {
    return existing;
  }

  db.prepare(`
    INSERT INTO student_identities (id, wallet_id, student_name, did, public_key, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    record.id,
    record.walletId,
    record.studentName,
    record.did,
    record.publicKey,
    record.createdAt
  );

  return getStudentIdentityByDid(record.did);
}

function getStudentIdentityById(id) {
  return db.prepare(`
    SELECT id, wallet_id AS walletId, student_name AS studentName, did, public_key AS publicKey, created_at AS createdAt
    FROM student_identities
    WHERE id = ?
  `).get(id) || null;
}

function getStudentIdentityByWalletId(walletId) {
  return db.prepare(`
    SELECT id, wallet_id AS walletId, student_name AS studentName, did, public_key AS publicKey, created_at AS createdAt
    FROM student_identities
    WHERE wallet_id = ?
  `).get(walletId) || null;
}

function getStudentIdentityByDid(did) {
  return db.prepare(`
    SELECT id, wallet_id AS walletId, student_name AS studentName, did, public_key AS publicKey, created_at AS createdAt
    FROM student_identities
    WHERE did = ?
  `).get(did) || null;
}

function createVerifiableCredentialRecord(record) {
  db.prepare(`
    INSERT INTO verifiable_credentials (
      id,
      credential_id,
      wallet_id,
      issuer_did,
      student_did,
      issuer_public_key,
      vc_json,
      signature,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    record.id,
    record.credentialId,
    record.walletId,
    record.issuerDid,
    record.studentDid,
    record.issuerPublicKey,
    JSON.stringify(record.vcPayload),
    record.signature,
    record.createdAt
  );

  return getVerifiableCredentialById(record.id);
}

function getVerifiableCredentialById(id) {
  const row = db.prepare(`
    SELECT
      id,
      credential_id AS credentialId,
      wallet_id AS walletId,
      issuer_did AS issuerDid,
      student_did AS studentDid,
      issuer_public_key AS issuerPublicKey,
      vc_json AS vcJson,
      signature,
      created_at AS createdAt
    FROM verifiable_credentials
    WHERE id = ?
  `).get(id);

  if (!row) {
    return null;
  }

  try {
    return {
      ...row,
      vc: JSON.parse(row.vcJson || '{}')
    };
  } catch (error) {
    return {
      ...row,
      vc: {}
    };
  }
}

function getVerifiableCredentialByCredentialId(credentialId) {
  const row = db.prepare(`
    SELECT
      id,
      credential_id AS credentialId,
      wallet_id AS walletId,
      issuer_did AS issuerDid,
      student_did AS studentDid,
      issuer_public_key AS issuerPublicKey,
      vc_json AS vcJson,
      signature,
      created_at AS createdAt
    FROM verifiable_credentials
    WHERE credential_id = ?
    ORDER BY created_at DESC
    LIMIT 1
  `).get(credentialId);

  if (!row) {
    return null;
  }

  try {
    return {
      ...row,
      vc: JSON.parse(row.vcJson || '{}')
    };
  } catch (error) {
    return {
      ...row,
      vc: {}
    };
  }
}

function getWalletCredentials(walletId) {
  const rows = db.prepare(`
    SELECT
      vc.id,
      vc.credential_id AS credentialId,
      vc.wallet_id AS walletId,
      vc.issuer_did AS issuerDid,
      vc.student_did AS studentDid,
      vc.issuer_public_key AS issuerPublicKey,
      vc.vc_json AS vcJson,
      vc.signature,
      vc.created_at AS createdAt,
      credentials.status AS status,
      credentials.blockchain_status AS blockchainStatus
    FROM verifiable_credentials AS vc
    LEFT JOIN credentials ON credentials.id = vc.credential_id
    WHERE vc.wallet_id = ?
    ORDER BY vc.created_at DESC
  `).all(walletId);

  return rows.map((row) => {
    try {
      return {
        ...row,
        vc: JSON.parse(row.vcJson || '{}')
      };
    } catch (error) {
      return {
        ...row,
        vc: {}
      };
    }
  });
}

function createAiAnalysisResult(record) {
  db.prepare(`
    INSERT INTO ai_analysis_results (
      id,
      credential_id,
      file_hash,
      file_type,
      score,
      classification,
      analysis_json,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    record.id,
    record.credentialId || null,
    record.fileHash,
    record.fileType,
    record.score,
    record.classification,
    JSON.stringify(record.analysis),
    record.createdAt
  );

  return getAiAnalysisById(record.id);
}

function getAiAnalysisById(id) {
  const row = db.prepare(`
    SELECT
      id,
      credential_id AS credentialId,
      file_hash AS fileHash,
      file_type AS fileType,
      score,
      classification,
      analysis_json AS analysisJson,
      created_at AS createdAt
    FROM ai_analysis_results
    WHERE id = ?
  `).get(id);

  if (!row) return null;
  return { ...row, analysis: JSON.parse(row.analysisJson) };
}

function getAiAnalysesByCredentialId(credentialId) {
  const rows = db.prepare(`
    SELECT
      id,
      credential_id AS credentialId,
      file_hash AS fileHash,
      file_type AS fileType,
      score,
      classification,
      analysis_json AS analysisJson,
      created_at AS createdAt
    FROM ai_analysis_results
    WHERE credential_id = ?
    ORDER BY created_at DESC
  `).all(credentialId);

  return rows.map((row) => ({ ...row, analysis: JSON.parse(row.analysisJson) }));
}

function createVerificationLog(credentialId, result) {
  const stmt = db.prepare(`
    INSERT INTO verification_logs (credential_id, verified_at, result)
    VALUES (?, ?, ?)
  `);

  stmt.run(credentialId, new Date().toISOString(), result);
}

function getDashboardStats() {
  return db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM credentials) AS totalCredentials,
      (SELECT COUNT(*) FROM credentials WHERE status = 'VALID') AS validCredentials,
      (SELECT COUNT(*) FROM credentials WHERE status = 'REVOKED') AS revokedCredentials,
      (SELECT COUNT(*) FROM verification_logs) AS totalVerifications
  `).get();
}

function getRecentVerifications(limit = 10) {
  return db.prepare(`
    SELECT
      credential_id AS credentialId,
      result,
      verified_at
    FROM verification_logs
    ORDER BY verified_at DESC, id DESC
    LIMIT ?
  `).all(limit);
}

function formatCredential(row) {
  return {
    id: row.id,
    studentName: row.student_name,
    degree: row.degree,
    university: row.university,
    graduationYear: row.graduation_year,
    issuedAt: row.issued_at,
    hash: row.hash,
    status: row.status,
    blockchainTxHash: row.blockchain_tx_hash,
    blockchainStatus: row.blockchain_status
  };
}

module.exports = {
  db,
  createCredential,
  saveIssuedCredential,
  getAllCredentials,
  getCredentialById,
  revokeCredential,
  deleteCredentialById,
  setCredentialBlockchainMetadata,
  getCredentialByHash,
  createStudentIdentity,
  getStudentIdentityById,
  getStudentIdentityByWalletId,
  getStudentIdentityByDid,
  setIssuerIdentity,
  createVerifiableCredentialRecord,
  getVerifiableCredentialById,
  getVerifiableCredentialByCredentialId,
  getWalletCredentials,
  getIssuerIdentityByDid,
  createAiAnalysisResult,
  getAiAnalysisById,
  getAiAnalysesByCredentialId,
  getUserByUsername,
  createInitialIssuer,
  createVerificationLog,
  getDashboardStats,
  getRecentVerifications
};