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

util.isNonEmptyString = util.StringValidator(/\S/);

util.decodeToken = function (token) {
    const [headerPart, payloadPart] = token.split('.');
    return {
        header:  JSON.parse(Buffer.from(headerPart, 'base64')),
        payload: JSON.parse(Buffer.from(payloadPart, 'base64'))
    };
};

util.decodeTokenHeader = function (token) {
    const headerPart = token.split('.')[0];
    return JSON.parse(Buffer.from(headerPart, 'base64'));
};

util.decodeTokenPayload = function (token) {
    const payloadPart = token.split('.')[1];
    return JSON.parse(Buffer.from(payloadPart, 'base64'));
};

util.isTokenHeader = function (value) {
    return util.isObject(value)
        && (util.isNull(value.alg) || util.isString(value.alg))
        && (util.isNull(value.typ) || util.isString(value.typ))
        && (util.isNull(value.kid) || util.isString(value.kid));
};

util.isTokenPayload = function (value) {
    return util.isObject(value)
        && (util.isNull(value.iss) || util.isString(value.iss))
        && (util.isNull(value.sub) || util.isString(value.sub))
        && (util.isNull(value.aud) || util.isString(value.aud))
        && (util.isNull(value.iat) || util.isFiniteNumber(value.iat))
        && (util.isNull(value.nbf) || util.isFiniteNumber(value.nbf))
        && (util.isNull(value.exp) || util.isFiniteNumber(value.exp));
};

Object.freeze(util);
module.exports = util;
