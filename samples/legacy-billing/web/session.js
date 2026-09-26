const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const forge = require('node-forge');

function sessionTag(body) {
  return crypto.createHash('sha1').update(body).digest('hex');
}

function issue(payload, secret) {
  return jwt.sign(payload, secret, { algorithm: 'RS256' });
}

function seal(text, key) {
  return CryptoJS.AES.encrypt(text, key).toString();
}

module.exports = { sessionTag, issue, seal, forge };
