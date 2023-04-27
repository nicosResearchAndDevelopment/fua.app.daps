const
    {URLSearchParams}    = require('url'),
    fetch                = require('node-fetch'),
    util                 = require('./util.daps.js'),
    model                = require('./model.daps.js'),
    ServerAgent          = require('@nrd/fua.agent.server'),
    // jose = require('@nrd/fua.module.jose'),
    {jwtVerify, SignJWT} = require('jose');

// SEE https://git02.int.nsc.ag/spetrac/idsa-infomodel/-/tree/master/daps
// SEE https://github.com/International-Data-Spaces-Association/IDS-G/tree/main/Components/IdentityProvider/DAPS

class DAPSAgent extends ServerAgent {

    #datContextURL = 'https://w3id.org/idsa/contexts/context.jsonld';
    #datContext    = null;

    #build = () => Promise.reject(new Error('not initialized'));
    /** @type {fua.app.daps.model.DAPS} */
    #daps  = null;

    constructor(options = {}) {
        super(options);

        if (options.datContextURL) this.#datContextURL = options.datContextURL;
        if (options.datContext) this.#datContext = options.datContext;
    } // DAPSAgent#constructor

    async initialize(options = {}) {
        await super.initialize(options);

        if (!this.#datContext) {
            const response = await fetch(this.#datContextURL);
            util.assert(response.ok, 'expected to get a valid response from the contextURL');
            const result = JSON.parse(await response.text());
            util.assert(util.isObject(result['@context']), 'expected the context result to include an @context');
            this.#datContext = result['@context'];
        }

        this.#build = model.builder(this.space);
        this.#daps  = await this.#build(this.node);
        await this.#daps.load();

        return this;
    } // DAPSAgent#initialize

    /**
     * @param {DatRequestQuery} requestQuery
     * @param {Object} [param]
     * @returns {DatRequestParam}
     */
    parseDatRequestQuery(requestQuery, param) {
        util.assert(util.isString(requestQuery), 'expected requestQuery to be a string', TypeError);

        const queryParams = new URLSearchParams(requestQuery);

        // OAuth based grant type: client_credentials.
        util.assert(util.isString(queryParams.has('grant_type')), 'expected queryParams to include "grant_type"');
        util.assert(util.isString(queryParams.has('scope')), 'expected queryParams to include "scope"');
        // See JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants.
        // LINK https://tools.ietf.org/html/rfc7523
        util.assert(util.isString(queryParams.has('client_assertion_type')), 'expected queryParams to include "client_assertion_type"');
        // The signed and base64 encoded request token. Paste the example to jwt.io to see the decoded JWT.
        // The token is signed with the connectors private key belonging to the public key contained in the X.509 certificate.
        util.assert(util.isString(queryParams.has('client_assertion')), 'expected queryParams to include "client_assertion"');

        return Object.fromEntries(queryParams.entries());
    } // DAPSAgent#parseDatRequestQuery

    getDatRequestParam(param) {
        util.assert(util.isNull(param?.requestQuery) || util.isNonEmptyString(param.requestQuery),
            'expected param.requestQuery to be a non-empty string', TypeError);
        util.assert(util.isNull(param?.requestParam) || util.isObject(param.requestParam),
            'expected param.requestParam to be an object', TypeError);
        util.assert(param?.requestParam || param?.requestQuery,
            'expected param to contain one of requestQuery or requestParam');

        const
            datRequestQuery = param.requestQuery || '',
            datRequestParam = param.requestParam || datRequestQuery && this.parseDatRequestQuery(datRequestQuery, param) || {};

        return datRequestParam;
    } // DAPSAgent#getDatRequestParam

    /**
     * @param {DatRequestToken} datRequestToken
     * @param {Object} [param]
     * @returns {Promise<DatRequestPayload>}
     */
    async parseDatRequestToken(datRequestToken, param) {
        util.assert(util.isString(datRequestToken), 'expected datRequestToken to be a string', TypeError);

        const
            datRequestPayload = util.decodeTokenPayload(datRequestToken),
            subjectKeyId      = datRequestPayload.sub || '',
            requestSubject    = await this.#daps.connectorCatalog.getConnectorPublicKey(subjectKeyId);

        util.assert(requestSubject, 'the subject "' + subjectKeyId + '" could not be found');

        const
            {publicKey}           = requestSubject,
            keyObject             = publicKey.createKeyObject(),
            verifyOptions         = {subject: publicKey.keyId},
            {payload: datRequest} = await jwtVerify(datRequestToken, keyObject, verifyOptions);

        return datRequest;
    } // DAPSAgent#parseDatRequestToken

    async getDatRequestPayload(param) {
        util.assert(util.isNull(param?.requestToken) || util.isNonEmptyString(param.requestToken),
            'expected param.requestToken to be a non-empty string', TypeError);
        util.assert(util.isNull(param?.requestPayload) || util.isTokenPayload(param.requestPayload),
            'expected param.requestPayload to be a token payload', TypeError);
        util.assert(param?.requestPayload || param?.requestToken || param?.requestParam || param?.requestQuery,
            'expected param to contain one of requestQuery, requestParam, requestToken or requestPayload');

        const
            datRequestParam   = this.getDatRequestParam(param),
            datRequestToken   = param.requestToken || datRequestParam.client_assertion || '',
            datRequestPayload = param.requestPayload || await this.parseDatRequestToken(datRequestToken, param);

        return datRequestPayload;
    } // DAPSAgent#getDatRequestPayload

    /**
     * @param {Object} [param]
     * @returns {DatHeader}
     */
    createDatHeader(param) {
        const
            // TODO find a useful way to select a private key
            // privateKey = this.#daps.privateKeys.find(key => key.keyType === util.iri.RSA),
            privateKey = this.#daps.privateKeys[0],
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
    } // DAPSAgent#createDatHeader

    /**
     * @param {Object} [param]
     * @param {DatRequestQuery} [param.requestQuery]
     * @param {DatRequestParam} [param.requestParam]
     * @param {DatRequestToken} [param.requestToken]
     * @param {DatRequestPayload} [param.requestPayload]
     * @returns {Promise<DatPayload>}
     */
    async createDatPayload(param) {
        const
            datRequestParam   = this.getDatRequestParam(param),
            datRequestPayload = await this.getDatRequestPayload({requestParam: datRequestParam, ...param}),
            subjectKeyId      = datRequestPayload.sub || '',
            requestSubject    = await this.#daps.connectorCatalog.getConnectorPublicKey(subjectKeyId);

        util.assert(requestSubject, 'the subject "' + subjectKeyId + '" could not be found');

        const
            timestamp              = util.unixTime(),
            {connector, publicKey} = requestSubject,
            datPayload             = {
                /**
                 * The JSON-LD context containing the IDS classes, properties and instances.
                 * Must be "https://w3id.org/idsa/contexts/context.jsonld".
                 */
                '@context': this.#datContextURL,
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
                'iss': this.uri,
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
                'jti': util.uuid.v4(),
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
    } // DAPSAgent#createDatPayload

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
    async createDat(param) {
        util.assert(util.isNull(param?.header) || util.isTokenHeader(param.header),
            'expected param.header to be a token header', TypeError);
        util.assert(util.isNull(param?.payload) || util.isTokenPayload(param.payload),
            'expected param.payload to be a token payload', TypeError);

        const
            datHeader  = param.header || this.createDatHeader(param),
            datPayload = param.payload || await this.createDatPayload(param),
            jwtSign    = new SignJWT(datPayload).setProtectedHeader(datHeader),
            privateKey = await this.#daps.getPrivateKey(datHeader.kid),
            dat        = await jwtSign.sign(privateKey.createKeyObject());

        return dat;
    } // DAPSAgent#createDat

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
    async createDatResponse(param) {
        util.assert(util.isNull(param?.token) || util.isNonEmptyString(param.token),
            'expected param.token to be a non-empty string', TypeError);

        const
            datHeader   = param?.header || this.createDatHeader(param),
            dat         = param?.token || await this.createDat({header: datHeader, ...param}),
            datResponse = {
                alg:          datHeader.alg,
                typ:          'JWT',
                kid:          datHeader.kid,
                access_token: dat,
                signature:    null
            };

        return datResponse;
    } // DAPSAgent#createDatResponse

    /**
     * @returns {JsonWebKeySet}
     */
    createJWKS() {
        return this.#daps.createJWKS();
    } // DAPSAgent#createJWKS

    createAbout() {
        return {
            'issuer': this.#daps['@id']
            // TODO
            // 'authorization_endpoint':                           'https://omejdn-daps.nicos-rd.com:8082/auth/authorize',
            // 'token_endpoint':                                   'https://omejdn-daps.nicos-rd.com:8082/auth/token',
            // 'jwks_uri':                                         'https://omejdn-daps.nicos-rd.com:8082/auth/jwks.json',
            // 'scopes_supported':                                 ['idsc:IDS_CONNECTOR_ATTRIBUTES_ALL', 'openid'],
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
    } // DAPSAgent#createAbout

} // DAPSAgent

module.exports = DAPSAgent;
