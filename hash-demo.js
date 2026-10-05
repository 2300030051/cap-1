const { ethers } = require("ethers");

// Step A: our credential data (same shape as before)
const credential = {
  studentName: "Vishnu",
  degree: "B.Tech Computer Science",
  university: "Example University",
  graduationYear: 2026,
  cgpa: 8.7
};

// Step B: convert the object into a consistent text form (JSON)
const credentialString = JSON.stringify(credential);
console.log("Credential as text:", credentialString);

// Step C: hash that text
const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(credentialString));
console.log("Credential Hash:", credentialHash);

// Step D: prove tampering is detectable — change ONE value
const tamperedCredential = { ...credential, cgpa: 9.9 }; // faked a higher CGPA
const tamperedString = JSON.stringify(tamperedCredential);
const tamperedHash = ethers.keccak256(ethers.toUtf8Bytes(tamperedString));

console.log("Tampered Hash:  ", tamperedHash);
console.log("Hashes match?", credentialHash === tamperedHash);