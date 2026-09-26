const session = require('./session');

function start(cart) {
  return session.sessionTag(JSON.stringify(cart));
}

module.exports = { start };
