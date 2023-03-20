const
    tls_config = require('../../data/server/cert/tls-server/server.js');

exports.schema   = 'https';
exports.hostname = process.env.SERVER_HOST || 'nrd-daps.nicos-rd.com';
exports.port     = Number(process.env.SERVER_PORT || 8083);

exports.options = {
    key:  tls_config.key,
    cert: tls_config.cert
};
