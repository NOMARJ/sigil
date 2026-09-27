// Synthetic fixture: an HTTPS agent that accepts any certificate, and the
// same switch flipped for the whole process (TLS-004, TLS-005; Medium).
const https = require("https");

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });

module.exports = { agent };
