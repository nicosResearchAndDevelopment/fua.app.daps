const
    _util = require('@nrd/fua.core.util'),
    util  = exports = {
        ..._util,
        assert: _util.Assert('app.daps')
    };

util.pause = function (seconds) {
    return new Promise((resolve) => {
        if (seconds >= 0) setTimeout(resolve, 1e3 * seconds);
        else setImmediate(resolve);
    });
};

// /**
//  * @param {string} prefixIri
//  * @returns {function(string): string}
//  */
// util.ns = function (prefixIri) {
//     return function (iriSuffix) {
//         return prefixIri + iriSuffix;
//     };
// };
//
// util.ns.rdf  = util.ns('rdf:');
// util.ns.ids  = util.ns('ids:');
// util.ns.idsc = util.ns('idsc:');
// util.ns.daps = util.ns('daps:');
// util.ns.xsd  = util.ns('xsd:');

util.iri = Object.freeze({
    type: 'rdf:type',

    DAPS:               'ids:DAPS',
    ConnectorCatalog:   'ids:ConnectorCatalog',
    Connector:          'ids:Connector',
    SecurityProfile:    'ids:SecurityProfile',
    SecurityGuarantee:  'ids:SecurityGuarantee',
    PublicKey:          'ids:PublicKey',
    Endpoint:           'ids:Endpoint',
    ConnectorEndpoint:  'ids:ConnectorEndpoint',
    AuthInfo:           'ids:AuthInfo',
    connectorCatalog:   'ids:connectorCatalog',
    listedConnector:    'ids:listedConnector',
    securityProfile:    'ids:securityProfile',
    extendedGuarantee:  'ids:extendedGuarantee',
    publicKey:          'ids:publicKey',
    keyType:            'ids:keyType',
    keyValue:           'ids:keyValue',
    hasEndpoint:        'ids:hasEndpoint',
    hasDefaultEndpoint: 'ids:hasDefaultEndpoint',
    accessURL:          'ids:accessURL',
    authInfo:           'ids:authInfo',
    authService:        'ids:authService',
    authStandard:       'ids:authStandard',

    PrivateKey: 'daps:PrivateKey',
    privateKey: 'daps:privateKey',
    keyId:      'daps:keyId',

    BASE_SECURITY_PROFILE:     'idsc:BASE_SECURITY_PROFILE',
    AUDIT_NONE:                'idsc:AUDIT_NONE',
    INTEGRITY_PROTECTION_NONE: 'idsc:INTEGRITY_PROTECTION_NONE',
    USAGE_CONTROL_NONE:        'idsc:USAGE_CONTROL_NONE',
    RSA:                       'idsc:RSA',
    OAUTH2_JWT:                'idsc:OAUTH2_JWT',

    string:             'xsd:string',
    base64Binary:       'xsd:base64Binary',
    nonNegativeInteger: 'xsd:nonNegativeInteger'
});

Object.freeze(util);
module.exports = util;
