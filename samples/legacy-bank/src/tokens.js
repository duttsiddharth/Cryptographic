const jwt = require("jsonwebtoken");
const crypto = require("crypto");

function sign(payload, key) {
  return jwt.sign(payload, key, { algorithm: "RS256" });
}
function legacyFingerprint(data) {
  return crypto.createHash("sha1").update(data).digest("hex");
}
module.exports = { sign, legacyFingerprint };
