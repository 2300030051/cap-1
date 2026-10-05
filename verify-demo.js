function verifyCredential(credential) {
  if (credential.revoked) {
    return "INVALID — credential was revoked";
  }
  if (!credential.issuer) {
    return "INVALID — no issuer found";
  }
  return "VALID — issued by " + credential.issuer;
}

const cred1 = { studentName: "Vishnu", issuer: "Example University", revoked: false };
const cred2 = { studentName: "Priya", issuer: "Example University", revoked: true };

console.log(verifyCredential(cred1));
console.log(verifyCredential(cred2));