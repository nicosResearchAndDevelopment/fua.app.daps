const
    path             = require('path'),
    __root           = path.join(__dirname, '../..'),
    tls_config       = require('../../cert/tls-server/server.js'),
    connector_config = require('../../cert/connector/client.js');

exports.server = {
    schema:   'https',
    hostname: 'nrd-daps.nicos-rd.com',
    port:     8082,
    options:  {
        key:  tls_config.key,
        cert: tls_config.cert
    }
};

exports.space = {
    context: require('@nrd/fua.resource.data/context'),
    store:   {
        module:  '@nrd/fua.module.persistence.filesystem',
        options: {
            defaultFile: 'file://data.ttl',
            loadFiles:   [
                {
                    'dct:identifier': path.join(__root, 'data/load.json'),
                    'dct:format':     'application/fua.load+json'
                },
                require('@nrd/fua.resource.ontology/rdf'),
                require('@nrd/fua.resource.ontology/rdfs'),
                require('@nrd/fua.resource.ontology/owl'),
                require('@nrd/fua.resource.ontology/foaf'),
                require('@nrd/fua.resource.ontology/odrl')
            ]
        }
    }
};
