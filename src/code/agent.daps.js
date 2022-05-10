const
    path              = require('path'),
    crypto            = require('crypto'),
    {URLSearchParams} = require('url'),
    fetch             = require('node-fetch'),
    util              = require('./util.daps.js'),
    model             = require('./model.daps.js'),
    ServerAgent       = require('@nrd/fua.agent.server'),
    // jose = require('@nrd/fua.module.jose'),
    {
        decodeProtectedHeader, jwtVerify, SignJWT
    }                 = require('jose');

// SEE https://git02.int.nsc.ag/spetrac/idsa-infomodel/-/tree/master/daps
// SEE https://github.com/International-Data-Spaces-Association/IDS-G/tree/master/core/DAPS

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

        util.assert(util.isString(queryParams.has('grant_type')), 'expected queryParams to include "grant_type"');
        util.assert(util.isString(queryParams.has('scope')), 'expected queryParams to include "scope"');
        util.assert(util.isString(queryParams.has('client_assertion_type')), 'expected queryParams to include "client_assertion_type"');
        util.assert(util.isString(queryParams.has('client_assertion')), 'expected queryParams to include "client_assertion"');

        return Object.fromEntries(queryParams.entries());
    } // DAPSAgent#parseDatRequestQuery

    /**
     * @param {DatRequestToken} datRequestToken
     * @param {Object} [param]
     * @returns {Promise<DatRequestPayload>}
     */
    async parseDatRequestToken(datRequestToken, param) {
        util.assert(util.isString(datRequestToken), 'expected datRequestToken to be a string', TypeError);
        const datRequestHeader = await decodeProtectedHeader(datRequestToken);
        util.assert(datRequestHeader.sub, 'expected datRequestHeader.sub to be a string');

        const subject = await this.#daps.connectorCatalog.getConnectorPublicKey(datRequestHeader.sub);
        util.assert(subject, 'the subject ' + datRequestHeader.sub + ' could not be found');

        const
            subjectPublicKey      = subject.publicKey.createKeyObject(),
            verifyOptions         = {subject: subject.publicKey.keyId},
            {payload: datRequest} = await jwtVerify(datRequestToken, subjectPublicKey, verifyOptions);

        return datRequest;
    } // DAPSAgent#parseDatRequestToken

    /**
     * @param {Object} [param]
     * @returns {DatHeader}
     */
    createDatHeader(param) {
        const
            privateKey = this.#daps.privateKeys[0],
            // privateKey = this.#daps.privateKeys.find(key => key.keyType === util.iri.RSA),
            datHeader  = {
                alg: 'RS256',
                typ: 'at+jwt',
                // kid: 'default'
                kid: privateKey.keyId
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
        util.assert(util.isNull(param?.requestQuery) || util.isNonEmptyString(param.requestQuery),
            'expected param.requestQuery to be a non-empty string', TypeError);
        util.assert(util.isNull(param?.requestParam) || util.isObject(param.requestParam),
            'expected param.requestParam to be an object', TypeError);
        util.assert(util.isNull(param?.requestToken) || util.isNonEmptyString(param.requestToken),
            'expected param.requestToken to be a non-empty string', TypeError);
        util.assert(util.isNull(param?.requestPayload) || util.isTokenPayload(param.requestPayload),
            'expected param.requestPayload to be a token payload', TypeError);
        util.assert(param?.requestPayload || param?.requestToken || param?.requestParam || param?.requestQuery,
            'expected param to contain one of requestQuery, requestParam, requestToken or requestPayload');

        const
            datRequestQuery   = param.requestQuery || '',
            datRequestParam   = param.requestParam || datRequestQuery && this.parseDatRequestQuery(datRequestQuery, param) || {},
            datRequestToken   = param.requestToken || datRequestParam.client_assertion || '',
            datRequestPayload = param.requestPayload || await this.parseDatRequestToken(datRequestToken, param),
            subjectKeyId      = datRequestPayload.sub || '',
            requestSubject    = this.#daps.connectorCatalog.getConnectorPublicKey(subjectKeyId);

        util.assert(requestSubject, 'the subject "' + subjectKeyId + '" could not be found');

        const
            timestamp              = util.unixTime(),
            {connector, publicKey} = requestSubject,
            datPayload             = {
                '@context': this.#datContextURL,
                '@type':    'DatPayload',
                'iss':      this.url,
                'sub':      publicKey.keyId,
                'aud':      'ALL',
                'iat':      timestamp,
                'nbf':      timestamp - 60,
                'exp':      timestamp + 60,
                /** The RDF connector entity as referred to by the DAT, with its URI included as the value. The value MUST be its accessible URI. */
                'referringConnector': connector.hasEndpoint.accessURL,
                /** The SecurityProfile supported by the Connector. */
                'securityProfile': connector.securityProfile,
                /** Reference to a security guarantee that, if used in combination with a security profile instance, overrides the respective guarantee of the given predefined instance. */
                'extendedGuarantee':    connector.extendedGuarantees,
                'transportCertsSha256': [],
                'scope':                ['IDS_CONNECTOR_ATTRIBUTES_ALL']
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

} // DAPSAgent

module.exports = DAPSAgent;
