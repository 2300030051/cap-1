function checkCredential(hasCertificate) {
  if (hasCertificate) {
    console.log("Credential found — proceeding to verify.");
  } else {
    console.log("No credential found — cannot verify.");
  }
}

checkCredential(true);
checkCredential(false);