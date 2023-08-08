const
    path = require('path');

// exports.uri = 'https://nrd-daps.nicos-rd.com/';
exports.uri = 'https://daps.tb.nicos-rd.com/';

exports.context = {
    ...require('@nrd/fua.resource.context'),

    'ids':  'https://w3id.org/idsa/core/',
    'idsc': 'https://w3id.org/idsa/code/',

    'fua':  'https://www.nicos-rd.com/fua#',
    'dom':  'https://www.nicos-rd.com/fua/domain#',
    'ecm':  'https://www.nicos-rd.com/fua/ecosystem#',
    'daps': 'https://www.nicos-rd.com/fua/daps#'
};

exports.store = {
    module:  '@nrd/fua.module.persistence.filesystem',
    options: {
        defaultFile: 'file://data.ttl',
        loadFiles:   [
            {
                'dct:identifier': path.join(__dirname, '../..', 'data/load.json'),
                'dct:format':     'application/fua.load+json'
            }
            // require('@nrd/fua.resource.ontology/rdf'),
            // require('@nrd/fua.resource.ontology/rdfs'),
            // require('@nrd/fua.resource.ontology/owl'),
            // require('@nrd/fua.resource.ontology/foaf'),
            // require('@nrd/fua.resource.ontology/odrl')
        ]
    }
};
