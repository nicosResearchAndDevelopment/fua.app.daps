const
    DAPS       = exports,
    identifier = '@nrd/fua.agent.daps',
    assert     = require('@nrd/fua.core.assert');

assert(!global[identifier], 'unable to load a second uncached version of the singleton ' + identifier);
Object.defineProperty(global, identifier, {value: DAPS, configurable: false, writable: false, enumerable: false});

// SEE https://git02.int.nsc.ag/spetrac/idsa-infomodel/-/tree/master/daps
// SEE https://github.com/International-Data-Spaces-Association/IDS-G/tree/main/Components/IdentityProvider/DAPS

const
    _DAPS                  = Object.create(null),
    Space                  = require('@nrd/fua.agent.space'),
    is                     = require('@nrd/fua.core.is'),
    ts                     = require('@nrd/fua.core.ts'),
    uuid                   = require('@nrd/fua.core.uuid'),
    model                  = require('./model.js'),
    {URL, URLSearchParams} = require('url'),
    {jwtVerify, SignJWT}   = require('jose'),
    crypto                 = require('crypto'),
    StoreConfig            = {
        module:  is.validator.string(/filesystem/i),
        options: (options) => is.object(options) && is.array(options.loadFiles)
    },
    InitializeOptions      = {
        uri:           is.string.token,
        datContextURL: is.validator.optional(is.string),
        datContext:    is.validator.optional(is.object),
        meta:          is.validator.optional(is.object)
    };

Object.defineProperties(DAPS, {
    root: {get: () => _DAPS.root || null, enumerable: true}
});

DAPS.prepareStore = async function (config) {
    assert.object(config, StoreConfig);

    const loadFiles = config.options.loadFiles;
    console.log(loadFiles);

    assert.todo('generate additional files from external certificates and append to load files'); // TODO
};

DAPS.initialize = async function (options = {}) {
    assert.object(options, InitializeOptions);
    assert(!_DAPS.initialized, 'already initialized');
    _DAPS.initialized = true;

    _DAPS.rootURI  = options.uri;
    _DAPS.rootNode = Space.getNode(_DAPS.rootURI);
    await _DAPS.rootNode.load();
    assert(_DAPS.rootNode.type, `node for "${_DAPS.rootURI}" not found in the space`);

    _DAPS.datContextURL = options.datContextURL || 'https://w3id.org/idsa/contexts/context.jsonld';
    _DAPS.datContext    = options.datContext || null;
    _DAPS.meta          = options.meta || {};

    if (!_DAPS.datContext) {
        const response = await fetch(_DAPS.datContextURL);
        assert(response.ok, 'invalid response from ' + _DAPS.datContextURL);
        const result = JSON.parse(await response.text());
        assert.object(result['@context']);
        _DAPS.datContext = result['@context'];
    }

    _DAPS.build = model.builder(Space.space);
    _DAPS.root  = await _DAPS.build(_DAPS.rootNode);
    await _DAPS.root.load();

    return DAPS;
};

DAPS.decodeToken = function (token) {
    const [headerPart, payloadPart] = token.split('.');
    return {
        header:  JSON.parse(Buffer.from(headerPart, 'base64')),
        payload: JSON.parse(Buffer.from(payloadPart, 'base64'))
    };
};

DAPS.decodeTokenHeader = function (token) {
    const headerPart = token.split('.')[0];
    return JSON.parse(Buffer.from(headerPart, 'base64'));
};

DAPS.decodeTokenPayload = function (token) {
    const payloadPart = token.split('.')[1];
    return JSON.parse(Buffer.from(payloadPart, 'base64'));
};

DAPS.isTokenHeader = function (value) {
    return is.object(value)
        && (is.null(value.alg) || is.string(value.alg))
        && (is.null(value.typ) || is.string(value.typ))
        && (is.null(value.kid) || is.string(value.kid));
};

DAPS.isTokenPayload = function (value) {
    return is.object(value)
        && (is.null(value.iss) || is.string(value.iss))
        && (is.null(value.sub) || is.string(value.sub))
        && (is.null(value.aud) || is.string(value.aud) || is.array.strings(value.aud))
        && (is.null(value.iat) || is.number.float.finite(value.iat))
        && (is.null(value.nbf) || is.number.float.finite(value.nbf))
        && (is.null(value.exp) || is.number.float.finite(value.exp))
        && (is.null(value.jti) || is.string(value.jti));
};

_DAPS.canonicalReviver = function (key, value) {
    if (is.object(value) && !is.array(value)) {
        const sortedEntries = Object.entries(value)
            .sort(([keyA], [keyB]) => keyA < keyB ? -1 : 1);
        return Object.fromEntries(sortedEntries);
    } else {
        return value;
    }
};

_DAPS.createChecksum = function (value) {
    if (is.string(value)) {
        return crypto.createHash('sha256').update(value).digest('hex');
    }
    if (is.object(value)) {
        const canonical = JSON.parse(JSON.stringify(value), _DAPS.canonicalReviver);
        return _DAPS.createChecksum(JSON.stringify(canonical));
    }
};

/**
 * @param {DatRequestQuery} requestQuery
 * @param {Object} [param]
 * @returns {DatRequestParam}
 */
DAPS.parseDatRequestQuery = function (requestQuery, param) {
    assert.string(requestQuery);
    const queryParams = new URLSearchParams(requestQuery);

    // OAuth based grant type: client_credentials.
    assert(queryParams.has('grant_type'), 'expected queryParams to include "grant_type"');
    assert(queryParams.has('scope'), 'expected queryParams to include "scope"');
    // See JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants.
    // LINK https://tools.ietf.org/html/rfc7523
    assert(queryParams.has('client_assertion_type'), 'expected queryParams to include "client_assertion_type"');
    // The signed and base64 encoded request token. Paste the example to jwt.io to see the decoded JWT.
    // The token is signed with the connectors private key belonging to the public key contained in the X.509 certificate.
    assert(queryParams.has('client_assertion'), 'expected queryParams to include "client_assertion"');

    return Object.fromEntries(queryParams.entries());
};

DAPS.getDatRequestParam = function (param) {
    assert(is.null(param?.requestQuery) || is.string.nonempty(param.requestQuery),
        'expected param.requestQuery to be a non-empty string', TypeError);
    assert(is.null(param?.requestParam) || is.object(param.requestParam),
        'expected param.requestParam to be an object', TypeError);
    assert(param?.requestParam || param?.requestQuery,
        'expected param to contain one of requestQuery or requestParam');

    const
        datRequestQuery = param.requestQuery || '',
        datRequestParam = param.requestParam || datRequestQuery && DAPS.parseDatRequestQuery(datRequestQuery, param) || {};

    return datRequestParam;
};

/**
 * @param {DatRequestToken} datRequestToken
 * @param {Object} [param]
 * @returns {Promise<DatRequestPayload>}
 */
DAPS.parseDatRequestToken = async function (datRequestToken, param) {
    assert.string(datRequestToken);

    const
        datRequestPayload = DAPS.decodeTokenPayload(datRequestToken),
        subjectKeyId      = datRequestPayload.sub || '',
        requestSubject    = await _DAPS.root.connectorCatalog.getConnectorPublicKey(subjectKeyId);

    assert(requestSubject, 'the subject "' + subjectKeyId + '" could not be found');

    const
        {publicKey}           = requestSubject,
        keyObject             = publicKey.createKeyObject(),
        verifyOptions         = {subject: publicKey.keyId},
        {payload: datRequest} = await jwtVerify(datRequestToken, keyObject, verifyOptions);

    return datRequest;
};

DAPS.getDatRequestPayload = async function (param) {
    assert(is.null(param?.requestToken) || is.string.nonempty(param.requestToken),
        'expected param.requestToken to be a non-empty string', TypeError);
    assert(is.null(param?.requestPayload) || DAPS.isTokenPayload(param.requestPayload),
        'expected param.requestPayload to be a token payload', TypeError);
    assert(param?.requestPayload || param?.requestToken || param?.requestParam || param?.requestQuery,
        'expected param to contain one of requestQuery, requestParam, requestToken or requestPayload');

    const
        datRequestParam   = DAPS.getDatRequestParam(param),
        datRequestToken   = param.requestToken || datRequestParam.client_assertion || '',
        datRequestPayload = param.requestPayload || await DAPS.parseDatRequestToken(datRequestToken, param);

    return datRequestPayload;
};

/**
 * @param {Object} [param]
 * @returns {DatHeader}
 */
DAPS.createDatHeader = function (param) {
    const
        // TODO find a useful way to select a private key
        // privateKey = _DAPS.root.privateKeys.find(key => key.keyType === IRI.RSA),
        privateKey = _DAPS.root.privateKeys[0],
        datHeader  = {
            /**
             * The token type. Must be "JWT".
             */
            typ: 'JWT',
            /**
             * Key id used to sign that token. Must match the jwks.json entry
             * found at daps-url/.well-known/jwks.json
             */
            kid: privateKey.keyId,
            /**
             * Algorithm used to sign the token.
             */
            alg: 'RS256'
        };
    return datHeader;
};

/**
 * @param {Object} [param]
 * @param {DatRequestQuery} [param.requestQuery]
 * @param {DatRequestParam} [param.requestParam]
 * @param {DatRequestToken} [param.requestToken]
 * @param {DatRequestPayload} [param.requestPayload]
 * @returns {Promise<DatPayload>}
 */
DAPS.createDatPayload = async function (param) {
    const
        datRequestParam   = DAPS.getDatRequestParam(param),
        datRequestPayload = await DAPS.getDatRequestPayload({requestParam: datRequestParam, ...param}),
        subjectKeyId      = datRequestPayload.sub || '',
        requestSubject    = await _DAPS.root.connectorCatalog.getConnectorPublicKey(subjectKeyId);

    assert(requestSubject, 'the subject "' + subjectKeyId + '" could not be found');

    const
        timestamp              = ts.unix(),
        {connector, publicKey} = requestSubject,
        datPayload             = {
            /**
             * The JSON-LD context containing the IDS classes, properties and instances.
             * Must be "https://w3id.org/idsa/contexts/context.jsonld".
             */
            '@context': _DAPS.datContextURL,
            /**
             * In the context of the IDS, the DAT payload is an RDF instance
             * and therefore must state that it has "@type" : "ids:DatPayload".
             */
            '@type': 'ids:DatPayload',
            /**
             * According to RFC 7519 Sec. 4.1.1, the issuer is the component which created and signed the JWT.
             * In the context of the IDS, this must be a valid DAPS.
             * The "iss" value must be a valid URL for the DAPS such as "https://daps.aisec.fraunhofer.de".
             */
            'iss': _DAPS.rootURI,
            /**
             * Subject the requesting connector the token is created for. This is the connector requesting the DAT.
             * The sub value must be the combined entry of the SKI and AKI of the IDS X509 as presented in Sec. 4.2.1.
             */
            'sub': publicKey.keyId,
            /**
             * Expiration date of the token. Can be chosen freely but should be limited
             * to a short period of time (e.g., one minute).
             */
            'exp': timestamp + 60,
            /**
             * Unique identifier of the jwt.
             */
            'jti': uuid.v4(),
            /**
             * Timestamp the token has been issued.
             */
            'iat': timestamp,
            /**
             * "Valid not before" (nbf): for practical reasons this should be identical to iat.
             * If systems time is not aynchronized with the DAPS, the request token
             * will be rejected (so, nbf is in the future).
             */
            'nbf': timestamp - 1,
            /**
             * The audience of the token. This can limit the validity for certain connectors.
             * Currently, only "idsc:IDS_CONNECTORS_ALL" is supported.
             * REM V3 change: "aud" is (in general) an array, but may be a string if it only contains one value.
             * Implementers are advised to either use an off-the-shelf JWT parsing library.
             */
            'aud': ['idsc:IDS_CONNECTORS_ALL'],
            /**
             * List of scopes. Currently, the scope is limited to "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL"
             * but can be used for claim scoping purposes in the future.
             * REM V3 change: "scopes" has been changed to "scope" in accordance
             * with https://www.rfc-editor.org/rfc/rfc9068.html#name-authorization-claims.
             */
            'scope': datRequestParam['scope'] || 'idsc:IDS_CONNECTOR_ATTRIBUTES_ALL',
            /**
             * States that the requesting connector conforms to a certain security profile
             * and has been certified to do so. The value must be an instance
             * of the ids:SecurityProfile class, e.g. "idsc:TRUST_SECURITY_PROFILE".
             */
            'securityProfile': connector.securityProfile,
            /**
             * The URI of the subject, the connector represented by the DAT.
             * Is used to connect identifier of the connector with the self-description identifier
             * as defined by the IDS Information Model. A receiving connector can use this information
             * to request more information at a Broker or directly by dereferencing this URI.
             */
            'referringConnector': connector.hasEndpoint.accessURL,
            /**
             * Contains the public keys of the used transport certificates.
             * The identifying X509 certificate should not be used for the communication encryption.
             * Therefore, the receiving party needs to connect the identity of a connector
             * by relating its hostname (from the communication encryption layer)
             * and the used private/public key pair, with its IDS identity claim of the DAT.
             * The public transportation key must be one of the "transportCertsSha256" values.
             * Otherwise, the receiving connector must expect that the requesting connector
             * is using a false identity claim.
             */
            'transportCertsSha256': connector.transportCertsSha256,
            /**
             * In case a connector fulfills a certain security profile but deviates for a subset of attributes,
             * it can inform the receiving connector about its actual security features.
             * This can only happen if a connector reaches a higher level for a certain security attribute
             * than the actual reached certification asks for. A deviation to lower levels is not possible,
             * as this would directly invalidate the complete certification level.
             */
            'extendedGuarantee': connector.extendedGuarantees,
            /**
             * REM V3 change: "client_id" was added. With the used client_credentials grant, it is equal to the "sub" claim.
             */
            'client_id': publicKey.keyId
        };

    return datPayload;
};

/**
 * @param {Object} [param]
 * @param {DatHeader} [param.header]
 * @param {DatPayload} [param.payload]
 * @param {DatRequestQuery} [param.requestQuery]
 * @param {DatRequestParam} [param.requestParam]
 * @param {DatRequestToken} [param.requestToken]
 * @param {DatRequestPayload} [param.requestPayload]
 * @returns {Promise<DynamicAttributeToken>}
 */
DAPS.createDat = async function (param) {
    assert(is.null(param?.header) || DAPS.isTokenHeader(param.header),
        'expected param.header to be a token header', TypeError);
    assert(is.null(param?.payload) || DAPS.isTokenPayload(param.payload),
        'expected param.payload to be a token payload', TypeError);

    const
        datHeader  = param.header || DAPS.createDatHeader(param),
        datPayload = param.payload || await DAPS.createDatPayload(param),
        jwtSign    = new SignJWT(datPayload).setProtectedHeader(datHeader),
        privateKey = await _DAPS.root.getPrivateKey(datHeader.kid),
        dat        = await jwtSign.sign(privateKey.createKeyObject());

    return dat;
};

/**
 * @param {Object} [param]
 * @param {DynamicAttributeToken} [param.token]
 * @param {DatHeader} [param.header]
 * @param {DatPayload} [param.payload]
 * @param {DatRequestQuery} [param.requestQuery]
 * @param {DatRequestParam} [param.requestParam]
 * @param {DatRequestToken} [param.requestToken]
 * @param {DatRequestPayload} [param.requestPayload]
 * @returns {Promise<DatResponseObject>}
 */
DAPS.createDatResponse = async function (param) {
    assert(is.null(param?.token) || is.string.nonempty(param.token),
        'expected param.token to be a non-empty string', TypeError);

    const
        datHeader   = param?.header || DAPS.createDatHeader(param),
        dat         = param?.token || await DAPS.createDat({header: datHeader, ...param}),
        datResponse = {
            alg:          datHeader.alg,
            typ:          'JWT',
            kid:          datHeader.kid,
            access_token: dat,
            signature:    null
        };

    return datResponse;
};

/**
 * @returns {JsonWebKeySet}
 */
DAPS.createJWKS = function () {
    return _DAPS.root.createJWKS();
};

DAPS.createAbout = function () {
    return {
        'issuer':           _DAPS.root['@id'],
        'token_endpoint':   _DAPS.meta.tokenPath && new URL(_DAPS.meta.tokenPath, _DAPS.rootURI) || undefined,
        'jwks_uri':         _DAPS.meta.jwksPath && new URL(_DAPS.meta.jwksPath, _DAPS.rootURI) || undefined,
        'scopes_supported': ['idsc:IDS_CONNECTOR_ATTRIBUTES_ALL']
        // TODO
        // 'authorization_endpoint':                           'https://omejdn-daps.nicos-rd.com:8082/auth/authorize',
        // 'response_types_supported':                         ['code'],
        // 'response_modes_supported':                         ['query', 'fragment', 'form_post'],
        // 'grant_types_supported':                            ['authorization_code', 'client_credentials'],
        // 'token_endpoint_auth_methods_supported':            ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'],
        // 'token_endpoint_auth_signing_alg_values_supported': ['RS256', 'RS512', 'ES256', 'ES512'],
        // 'service_documentation':                            'https://github.com/Fraunhofer-AISEC/omejdn-server/wiki',
        // 'ui_locales_supported':                             [],
        // 'code_challenge_methods_supported':                 ['S256'],
        // 'tls_client_certificate_bound_access_tokens':       false,
        // 'mtls_endpoint_aliases':                            {},
        // 'require_signed_request_object':                    true,
        // 'pushed_authorization_request_endpoint':            'https://omejdn-daps.nicos-rd.com:8082/auth/par',
        // 'require_pushed_authorization_requests':            false,
        // 'authorization_response_iss_parameter_supported':   true,
        // 'end_session_endpoint':                             'https://omejdn-daps.nicos-rd.com:8082/auth/logout',
        // 'userinfo_endpoint':                                'https://omejdn-daps.nicos-rd.com:8082/auth/userinfo',
        // 'acr_values_supported':                             [],
        // 'subject_types_supported':                          ['public'],
        // 'id_token_signing_alg_values_supported':            ['RS256'],
        // 'id_token_encryption_alg_values_supported':         ['none'],
        // 'id_token_encryption_enc_values_supported':         ['none'],
        // 'userinfo_signing_alg_values_supported':            ['none'],
        // 'userinfo_encryption_alg_values_supported':         ['none'],
        // 'userinfo_encryption_enc_values_supported':         ['none'],
        // 'request_object_signing_alg_values_supported':      ['RS256', 'RS512', 'ES256', 'ES512'],
        // 'request_object_encryption_alg_values_supported':   ['none'],
        // 'request_object_encryption_enc_values_supported':   ['none'],
        // 'display_values_supported':                         ['page'],
        // 'claim_types_supported':                            ['normal'],
        // 'claims_supported':                                 [],
        // 'claims_locales_supported':                         [],
        // 'claims_parameter_supported':                       true,
        // 'request_parameter_supported':                      true,
        // 'request_uri_parameter_supported':                  true,
        // 'require_request_uri_registration':                 true,
        // 'signed_metadata':                                  '...'
    };
};

Object.freeze(DAPS);
module.exports = DAPS;
