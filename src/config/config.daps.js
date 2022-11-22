exports.server = require('./config.daps.server.js');
exports.space  = require('./config.daps.space.js');

exports.tokenPath = [
    '/token',
    '/auth/token'
];

exports.jwksPath = [
    '/jwks.json',
    '/.well-known/jwks.json',
    '/auth/jwks.json',
    '/auth/.well-known/jwks.json'
];

exports.aboutPath = [
    '/',
    '/about',
    '/.well-known/openid-configuration',
    '/auth/.well-known/openid-configuration'
];

exports.daps = {
    tokenPath: '/token',
    jwksPath:  '/.well-known/jwks.json',
    aboutPath: '/.well-known/openid-configuration'
};

exports.tweakDat = {
    pipeTweaks: [
        // '@type',
        // 'iss',
        // 'sub',
        // 'referringConnector',
        // 'securityProfile',
        // 'extendedGuarantee',
        // 'transportCertsSha256',
        // 'iat',
        // 'exp',
        // 'aud',
        // 'nbf',
        // 'scope',
        'custom'
    ],
    configPath: '/tweak'
};
