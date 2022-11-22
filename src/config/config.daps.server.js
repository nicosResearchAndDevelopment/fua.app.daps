const
    tls_config = require('../../cert/tls-server/server.js');

exports.schema   = 'https';
exports.hostname = 'nrd-daps.nicos-rd.com';
exports.port     = 8083;
exports.options  = {
    key:  tls_config.key,
    cert: tls_config.cert
};
