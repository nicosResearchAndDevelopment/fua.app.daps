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
    subprocess             = require('@nrd/fua.module.subprocess'),
    rdf                    = require('@nrd/fua.module.rdf'),
    {Dataset, TermFactory} = require('@nrd/fua.module.persistence'),
    tty                    = require('@nrd/fua.core.tty'),
    model                  = require('./model.js'),
    {URL, URLSearchParams} = require('url'),
    {jwtVerify, SignJWT}   = require('jose'),
    crypto                 = require('crypto'),
    path                   = require('path'),
    fs                     = require('fs/promises'),
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

_DAPS.baseURI           = 'https://daps.tb.nicos-rd.com/';
_DAPS.clientsFolderPath = '/var/opt/fua/daps/clients';
// _DAPS.clientsFolderPath = path.join(__dirname, '../../test/clients'); // TEMP

Object.defineProperties(DAPS, {
    root: {get: () => _DAPS.root || null, enumerable: true}
});

// NOTE alternatively the prepareStore method can be changed into a post-initialize method by using the model to create entities directly in the database
DAPS.prepareStore = async function (config) {
    assert.object(config, StoreConfig);
    assert(!_DAPS.initialized, 'already initialized');

    /** @type {Array<{
     *     name: string,
     *     files: {
     *         cert: string,
     *         [other: string]: string
     *     },
     *     id?: string,
     *     url?: string,
     *     cert?: string,
     *     hash?: string
     * }>} */
    let clientsDataArray = [];

    try {
        const clientFilesMap = new Map();
        for (let clientDirent of await fs.readdir(_DAPS.clientsFolderPath, {withFileTypes: true})) {
            if (!clientDirent.isFile()) continue;
            const lastDotIndex = clientDirent.name.lastIndexOf('.');
            if (lastDotIndex < 0) continue;
            const clientName = clientDirent.name.slice(0, lastDotIndex);
            const fileEnding = clientDirent.name.slice(lastDotIndex + 1);
            if (!clientName || !fileEnding) continue;
            if (!clientFilesMap.has(clientName)) clientFilesMap.set(clientName, {});
            const clientFiles       = clientFilesMap.get(clientName);
            clientFiles[fileEnding] = path.join(_DAPS.clientsFolderPath, clientDirent.name);
        }
        for (let [clientName, clientFiles] of clientFilesMap.entries()) {
            if (!clientFiles.cert) continue;
            clientsDataArray.push({
                name:  clientName,
                files: clientFiles
            });
        }
        if (clientsDataArray.length === 0) return void tty.log('skipped: ' + _DAPS.clientsFolderPath + ' has no additional certificates');
    } catch (err) {
        if (err.code === 'ENOENT') return void tty.log('skipped: ' + _DAPS.clientsFolderPath + ' does not exist');
        throw err;
    }

    const openssl = subprocess.ExecutionProcess('openssl', {
        cwd:      _DAPS.clientsFolderPath,
        verbose:  false,
        encoding: 'utf-8'
    });

    await Promise.all(clientsDataArray.map(async (clientData) => {
        const
            clientCertText = await openssl('x509', {
                in:    clientData.files.cert,
                noout: true,
                text:  true
            }),
            Subject_match  = /Subject:\s*(.*(?=[\r\n]))/.exec(clientCertText),
            SKI_match      = /X509v3 Subject Key Identifier:\s*(\S+(?=\s))/.exec(clientCertText),
            AKI_match      = /X509v3 Authority Key Identifier:\s*(\S+(?=\s))/.exec(clientCertText),
            CN_match       = Subject_match ? /CN = (\S+)$/.exec(Subject_match[1]) : null;

        if (!Subject_match || !SKI_match || !AKI_match || !CN_match) return;
        clientData.id  = SKI_match[1] + ':' + AKI_match[1];
        clientData.url = 'https://' + CN_match[1].replace('*.', '') + '/';

        const
            clientCert    = await fs.readFile(clientData.files.cert, 'utf-8'),
            clientCertRaw = clientCert.split('\n')
                .filter(line => !line.includes('-----'))
                .map(line => line.trim())
                .join('');

        clientData.cert = clientCertRaw;
        clientData.hash = crypto.createHash('sha256').update(clientCertRaw, 'base64').digest('hex');
    }));

    const tempFolderPath = path.join(__dirname, '../temp');
    await fs.mkdir(path.join(tempFolderPath, 'clients'), {recursive: true});

    const
        context         = {
            rdf:       'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
            rdfs:      'http://www.w3.org/2000/01/rdf-schema#',
            dct:       'http://purl.org/dc/terms/',
            xsd:       'http://www.w3.org/2001/XMLSchema#',
            ids:       'https://w3id.org/idsa/core/',
            idsc:      'https://w3id.org/idsa/code/',
            fua:       'https://www.nicos-rd.com/fua#',
            daps:      'https://www.nicos-rd.com/fua/daps#',
            connector: _DAPS.baseURI + 'connector#'
        },
        factory         = new TermFactory(context),
        /** @type {Record<string, (v?: string) => NamedNode>} */
        namespace       = Object.fromEntries(Object.entries(context).map(([key, value]) => [key, factory.namespace(value)])),
        catalogDataset  = new Dataset(null, factory),
        catalogNode     = namespace.connector(),
        catalogTempPath = path.join(tempFolderPath, 'catalog.ttl');

    await Promise.all(clientsDataArray.map(async (clientData) => {
        const
            clientDataset  = new Dataset(null, factory),
            clientNode     = namespace.connector(clientData.name),
            clientTempPath = path.join(tempFolderPath, 'clients', clientData.name + '.ttl');

        clientDataset.add(factory.quad(
            clientNode,
            namespace.rdf('type'),
            namespace.ids('Connector')
        ));

        clientDataset.add(factory.quad(
            clientNode,
            namespace.rdf('type'),
            namespace.ids('BaseConnector')
        ));

        clientDataset.add(factory.quad(
            clientNode,
            namespace.ids('securityProfile'),
            namespace.idsc('BASE_SECURITY_PROFILE')
        ));

        // clientDataset.add(factory.quad(
        //     clientNode,
        //     namespace.ids('extendedGuarantee'),
        //     namespace.idsc('...')
        // ));

        // clientDataset.add(factory.quad(
        //     clientNode,
        //     namespace.ids('transportCertsSha256'),
        //     factory.literal('...')
        // ));

        const publicKeyNode = factory.blankNode();

        clientDataset.add(factory.quad(
            clientNode,
            namespace.ids('publicKey'),
            publicKeyNode
        ));

        clientDataset.add(factory.quad(
            publicKeyNode,
            namespace.rdf('type'),
            namespace.ids('PublicKey')
        ));

        clientDataset.add(factory.quad(
            publicKeyNode,
            namespace.daps('keyId'),
            factory.literal(clientData.id)
        ));

        clientDataset.add(factory.quad(
            publicKeyNode,
            namespace.ids('keyType'),
            namespace.idsc('RSA')
        ));

        clientDataset.add(factory.quad(
            publicKeyNode,
            namespace.ids('keyValue'),
            factory.literal(clientData.cert, namespace.xsd('base64Binary'))
        ));

        const endpointNode = factory.blankNode();

        clientDataset.add(factory.quad(
            clientNode,
            namespace.ids('hasEndpoint'),
            endpointNode
        ));

        clientDataset.add(factory.quad(
            endpointNode,
            namespace.rdf('type'),
            namespace.ids('ConnectorEndpoint')
        ));

        clientDataset.add(factory.quad(
            endpointNode,
            namespace.ids('accessURL'),
            factory.literal(clientData.url, namespace.xsd('anyURI'))
        ));

        const authNode = factory.blankNode();

        clientDataset.add(factory.quad(
            clientNode,
            namespace.ids('authInfo'),
            authNode
        ));

        clientDataset.add(factory.quad(
            authNode,
            namespace.rdf('type'),
            namespace.ids('AuthInfo')
        ));

        clientDataset.add(factory.quad(
            authNode,
            namespace.ids('authService'),
            factory.namedNode(_DAPS.baseURI)
        ));

        clientDataset.add(factory.quad(
            authNode,
            namespace.ids('authStandard'),
            namespace.idsc('OAUTH2_JWT')
        ));

        const clientTTL = await rdf.serializeDataset(clientDataset, 'text/turtle');
        await fs.writeFile(clientTempPath, clientTTL);
        config.options.loadFiles.push({
            'dct:identifier': clientTempPath,
            'dct:format':     'text/turtle'
        });

        catalogDataset.add(factory.quad(
            catalogNode,
            namespace.ids('listedConnector'),
            namespace.connector(clientData.name)
        ));
    }));

    const catalogTTL = await rdf.serializeDataset(catalogDataset, 'text/turtle');
    await fs.writeFile(catalogTempPath, catalogTTL);
    config.options.loadFiles.push({
        'dct:identifier': catalogTempPath,
        'dct:format':     'text/turtle'
    });
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
