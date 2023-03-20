const fs          = require('fs'), path = require('path'), crypto = require('crypto');
const load        = (filename) => fs.readFileSync(path.join(__dirname, filename));
exports.meta      = require('./connector.json');
exports.pub       = load('./connector.pub');
exports.publicKey = crypto.createPublicKey(exports.pub);
exports.cert      = load('./connector.cert');
Object.freeze(exports);
