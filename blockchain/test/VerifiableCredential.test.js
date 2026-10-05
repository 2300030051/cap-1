const { expect } = require('chai');
const crypto = require('crypto');
const {
  signCredentialVC,
  verifyCredentialVC,
  verifyCredentialBinding
} = require('../../verifiableCredentialService');

describe('Local Verifiable Credential signatures', function () {
  let identity;
  let publicKey;

  beforeEach(function () {
    const keyPair = crypto.generateKeyPairSync('ed25519');
    identity = {
      did: 'did:academic:issuer:test-university',
      privateKey: keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    };
    publicKey = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  });

  it('verifies a signed credential independent of object key order', function () {
    const signed = signCredentialVC({
      type: ['VerifiableCredential', 'AcademicCredential'],
      issuer: identity.did,
      credentialSubject: { degree: 'BSc', studentName: 'Alice' }
    }, identity);
    const reordered = {
      credentialSubject: { studentName: 'Alice', degree: 'BSc' },
      issuer: identity.did,
      type: ['VerifiableCredential', 'AcademicCredential'],
      proof: signed.vc.proof
    };

    expect(verifyCredentialVC(signed.vc, publicKey)).to.equal(true);
    expect(verifyCredentialVC(reordered, publicKey)).to.equal(true);
  });

  it('rejects a modified credential and a missing proof', function () {
    const signed = signCredentialVC({
      type: ['VerifiableCredential'],
      credentialSubject: { degree: 'BSc' }
    }, identity);
    const modified = {
      ...signed.vc,
      credentialSubject: { degree: 'MSc' }
    };

    expect(verifyCredentialVC(modified, publicKey)).to.equal(false);
    expect(verifyCredentialVC({ credentialSubject: {} }, publicKey)).to.equal(false);
  });

  it('binds signed claims and proof DID to registered issuer and student identities', function () {
    const credential = {
      id: 'credential-binding-test',
      studentName: 'Alice Example',
      degree: 'BSc',
      university: 'Local University',
      graduationYear: 2026
    };
    const issuerDid = identity.did;
    const studentDid = 'did:academic:student:wallet-alice';
    const vc = signCredentialVC({
      credentialId: credential.id,
      issuer: issuerDid,
      credentialSubject: {
        id: studentDid,
        studentName: credential.studentName,
        degree: credential.degree,
        university: credential.university,
        graduationYear: credential.graduationYear
      }
    }, identity).vc;
    const vcRecord = {
      issuerDid,
      issuerPublicKey: publicKey,
      studentDid,
      walletId: 'wallet:alice'
    };
    const issuerIdentity = { did: issuerDid, publicKey };
    const studentIdentity = { did: studentDid, walletId: 'wallet:alice' };

    expect(verifyCredentialVC(vc, publicKey)).to.equal(true);
    expect(verifyCredentialBinding(vc, credential, vcRecord, issuerIdentity, studentIdentity)).to.equal(true);
    expect(verifyCredentialBinding(vc, credential, { ...vcRecord, studentDid: 'did:academic:student:wrong' }, issuerIdentity, studentIdentity)).to.equal(false);
    expect(verifyCredentialVC(vc, 'not a public key')).to.equal(false);
  });
});
