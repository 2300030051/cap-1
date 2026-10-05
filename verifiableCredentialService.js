const { signData, verifySignature } = require('./didService');

function createCredentialVC({ credential, issuerDid, studentDid }) {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'AcademicCredential'],
    issuer: issuerDid,
    credentialSubject: {
      id: studentDid,
      studentName: credential.studentName,
      degree: credential.degree,
      university: credential.university,
      graduationYear: credential.graduationYear
    },
    credentialId: credential.id,
    issuanceDate: credential.issuedAt,
    credentialStatus: {
      status: credential.status === 'REVOKED' ? 'REVOKED' : 'VALID'
    }
  };
}

function signCredentialVC(vc, identity) {
  const signature = signData(vc, identity.privateKey);
  const signedVc = {
    ...vc,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      proofPurpose: 'assertionMethod',
      verificationMethod: `${identity.did}#key-1`,
      jws: signature
    }
  };

  return {
    vc: signedVc,
    signature
  };
}

function verifyCredentialVC(signedVc, publicKeyPem) {
  if (!signedVc || !signedVc.proof || !signedVc.proof.jws) {
    return false;
  }

  try {
    const { proof, ...unsignedVc } = signedVc;
    return verifySignature(unsignedVc, proof.jws, publicKeyPem);
  } catch (error) {
    return false;
  }
}

function verifyCredentialBinding(signedVc, credential, vcRecord, issuerIdentity, studentIdentity) {
  if (!signedVc || !credential || !vcRecord || !issuerIdentity || !studentIdentity) {
    return false;
  }

  const subject = signedVc.credentialSubject || {};
  const proof = signedVc.proof || {};
  return signedVc.credentialId === credential.id &&
    signedVc.issuer === vcRecord.issuerDid &&
    signedVc.issuer === issuerIdentity.did &&
    vcRecord.issuerPublicKey === issuerIdentity.publicKey &&
    subject.id === vcRecord.studentDid &&
    subject.id === studentIdentity.did &&
    vcRecord.walletId === studentIdentity.walletId &&
    proof.verificationMethod === `${issuerIdentity.did}#key-1` &&
    subject.studentName === credential.studentName &&
    subject.degree === credential.degree &&
    subject.university === credential.university &&
    Number(subject.graduationYear) === Number(credential.graduationYear);
}

module.exports = {
  createCredentialVC,
  signCredentialVC,
  verifyCredentialVC,
  verifyCredentialBinding
};
