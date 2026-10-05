const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const IDENTITY_STORE_PATH = path.join(__dirname, 'data', 'local-identities.json');

function canonicalizeObject(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalizeObject(entry));
  }

  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((result, key) => {
        result[key] = canonicalizeObject(value[key]);
        return result;
      }, {});
  }

  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalizeObject(value));
}

function normalizeIdentifier(identifier) {
  const normalized = String(identifier || 'demo')
    .trim()
    .replace(/[^a-zA-Z0-9-_.]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();

  return normalized || 'demo';
}

function ensureIdentityStore() {
  fs.mkdirSync(path.dirname(IDENTITY_STORE_PATH), { recursive: true });

  if (!fs.existsSync(IDENTITY_STORE_PATH)) {
    fs.writeFileSync(IDENTITY_STORE_PATH, '{}', { encoding: 'utf8', mode: 0o600 });
  }

  fs.chmodSync(IDENTITY_STORE_PATH, 0o600);
}

function readIdentityStore() {
  ensureIdentityStore();

  try {
    const raw = fs.readFileSync(IDENTITY_STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (error) {
    return {};
  }
}

function writeIdentityStore(store) {
  ensureIdentityStore();
  fs.writeFileSync(IDENTITY_STORE_PATH, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.chmodSync(IDENTITY_STORE_PATH, 0o600);
}

function createDid(kind, identifier) {
  return `did:academic:${kind}:${normalizeIdentifier(identifier)}`;
}

function createIdentity(kind, identifier) {
  const normalizedIdentifier = normalizeIdentifier(identifier);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const did = createDid(kind, normalizedIdentifier);

  return {
    id: `${kind}:${normalizedIdentifier}`,
    kind,
    did,
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    createdAt: new Date().toISOString()
  };
}

function persistIdentity(identity) {
  if (!identity || typeof identity.kind !== 'string' || typeof identity.id !== 'string') {
    throw new Error('Invalid local identity.');
  }

  const prefix = `${identity.kind}:`;
  const identifier = identity.id.startsWith(prefix) ? identity.id.slice(prefix.length) : '';
  if (
    !identifier || identifier !== normalizeIdentifier(identifier) ||
    identity.did !== createDid(identity.kind, identifier) ||
    !identity.publicKey || !identity.privateKey
  ) {
    throw new Error('Invalid local identity.');
  }

  const store = readIdentityStore();
  if (store[identity.id]) {
    return store[identity.id];
  }

  store[identity.id] = identity;
  writeIdentityStore(store);
  return identity;
}

function loadOrCreateIdentity(kind, identifier) {
  const normalizedIdentifier = normalizeIdentifier(identifier);
  const identityKey = `${kind}:${normalizedIdentifier}`;
  const store = readIdentityStore();

  if (store[identityKey]) {
    return store[identityKey];
  }

  return persistIdentity(createIdentity(kind, normalizedIdentifier));
}

function getIdentity(kind, identifier) {
  const normalizedIdentifier = normalizeIdentifier(identifier);
  const store = readIdentityStore();
  return store[`${kind}:${normalizedIdentifier}`] || null;
}

function signData(data, privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  const buffer = Buffer.from(canonicalJson(data), 'utf8');
  return crypto.sign(null, buffer, key).toString('base64');
}

function verifySignature(data, signature, publicKeyPem) {
  const key = crypto.createPublicKey(publicKeyPem);
  const buffer = Buffer.from(canonicalJson(data), 'utf8');
  return crypto.verify(null, buffer, key, Buffer.from(signature, 'base64'));
}

module.exports = {
  createDid,
  createIdentity,
  persistIdentity,
  canonicalJson,
  loadOrCreateIdentity,
  getIdentity,
  normalizeIdentifier,
  signData,
  verifySignature
};
