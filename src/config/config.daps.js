const
    path       = require('path'),
    __root     = path.join(__dirname, '../..'),
    prodConfig = require('./config.daps.prod.js');

exports.server = prodConfig.server;

exports.space = {
    context: {
        ...require('@nrd/fua.resource.data/context'),

        'ids':  'https://w3id.org/idsa/core/',
        'idsc': 'https://w3id.org/idsa/code/',

        'fua':  'https://www.nicos-rd.com/fua#',
        'dom':  'https://www.nicos-rd.com/fua/domain#',
        'ecm':  'https://www.nicos-rd.com/fua/ecosystem#',
        'daps': 'https://www.nicos-rd.com/fua/daps#'
    },
    store:   {
        module:  '@nrd/fua.module.persistence.filesystem',
        options: {
            defaultFile: 'file://data.ttl',
            loadFiles:   [
                {
                    'dct:identifier': path.join(__root, 'data/load.json'),
                    'dct:format':     'application/fua.load+json'
                }
                // require('@nrd/fua.resource.ontology/rdf'),
                // require('@nrd/fua.resource.ontology/rdfs'),
                // require('@nrd/fua.resource.ontology/owl'),
                // require('@nrd/fua.resource.ontology/foaf'),
                // require('@nrd/fua.resource.ontology/odrl')
            ]
        }
    }
};

exports.daps = {
    tokenPath: [
        '/token',
        '/auth/token'
    ],
    jwksPath:  [
        '/.well-known/jwks.json',
        '/jwks.json',
        '/auth/jwks.json'
    ],
    aboutPath: [
        '/',
        '/about',
        '/auth/.well-known/openid-configuration'
    ],
    tweakDat:  {
        pipeRequestTweaks: [
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
        setupMatcherPath:  '/tweak'
    }
};
