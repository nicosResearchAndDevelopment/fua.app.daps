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
    #build         = () => Promise.reject(new Error('not initialized'));

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

        return this;
    } // DAPSAgent#initialize

    /**
     * @param {DatRequestQuery} requestQuery
     * @param {Object} [param]
     * @returns {Promise<DatRequestParam>}
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
        util.assert(datRequestHeader.sub && this.#clientKeys.has(datRequestHeader.sub), 'expected the dat request to contain a registered subject');

        const subjectPublicKey                                                       = this.getClientKey(datRequestHeader.sub),
              verifyOptions = {subject: datRequestHeader.sub}, {payload: datRequest} = await jwtVerify(datRequestToken, subjectPublicKey, verifyOptions);

        return datRequest;
    } // DAPSAgent#parseDatRequestToken

    createDatHeader(datRequest) {
        return {alg: 'RS256', kid: 'default'};
    } // DAPSAgent#createDatHeader

    async createDatPayload(datRequest) {
        util.assert(util.isString(datRequest?.sub), 'expected datRequest.sub to be a string', TypeError);
        const subjData = await this.getClientData(datRequest.sub);
        util.assert(subjData, 'the subject ' + datRequest.sub + ' could not be found');

        const timestamp = util.unixTime(), datPayload = {
            '@context': this.#datContextURL,
            '@type':    'DatPayload',
            'iss':      this.url,
            'sub':      datRequest.sub,
            'aud':      'ALL',
            'iat':      timestamp,
            'nbf':      timestamp - 60,
            'exp':      timestamp + 60,
            /** The RDF connector entity as referred to by the DAT, with its URI included as the value. The value MUST be its accessible URI. */
            'referringConnector': subjData.uri,
            /** The SecurityProfile supported by the Connector. */
            'securityProfile': subjData.securityProfile,
            /** Reference to a security guarantee that, if used in combination with a security profile instance, overrides the respective guarantee of the given predefined instance. */
            'extendedGuarantee':    subjData.extendedGuarantee,
            'transportCertsSha256': [],
            'scope':                ['IDS_CONNECTOR_ATTRIBUTES_ALL']
        };

        return datPayload;
    } // DAPSAgent#createDatPayload

    async createDat(datPayload, datHeader) {
        const jwtSign = new SignJWT(datPayload), dapsPrivateKey = this.getServerKey(datHeader.kid),
              dat                                               = await jwtSign.setProtectedHeader(datHeader).sign(dapsPrivateKey);

        return dat;
    } // DAPSAgent#createDat

    #serverKeys = new Map();
    #clientKeys = new Map();

    /**
     * @param {string} keyId
     * @param {string|Buffer|KeyObject} keyLike
     * @returns {void}
     */
    addServerKey(keyId, keyLike) {
        util.assert(util.isString(keyId), 'expected keyId to be a string', TypeError);
        util.assert(!this.#serverKeys.has(keyId), 'keyId (' + keyId + ') already in use');
        const privateKey = crypto.createPrivateKey(keyLike);
        this.#serverKeys.set(keyId, privateKey);
    } // DAPSAgent#addServerKey

    /**
     * @param {string} keyId
     * @returns {KeyObject}
     */
    getServerKey(keyId) {
        util.assert(util.isString(keyId), 'expected keyId to be a string', TypeError);
        return this.#serverKeys.get(keyId) || null;
    } // DAPSAgent#getServerKey

    /**
     * @param {string} keyId
     * @returns {void}
     */
    removeServerKey(keyId) {
        util.assert(util.isString(keyId), 'expected keyId to be a string', TypeError);
        util.assert(this.#serverKeys.has(keyId), 'keyId (' + keyId + ') not in use');
        this.#serverKeys.delete(keyId);
    } // DAPSAgent#removeServerKey

    /**
     * @returns {Promise<{keys: Array<JsonWebKey>}>}
     */
    async generateJWKS() {
        const keys = await Promise.all(Array.from(this.#serverKeys.entries()).map(async ([keyId, privateKey]) => {
            const jwk = await jose.jwk.serialize(crypto.createPublicKey(privateKey));
            return Object.assign({kid: keyId}, jwk);
        }));
        return {keys};
    } // DAPSAgent#generateJWKS

    /**
     * @param {string} keyId
     * @param {string|Buffer|KeyObject} keyLike
     * @returns {void}
     */
    addClientKey(keyId, keyLike) {
        util.assert(util.isString(keyId), 'expected keyId to be a string', TypeError);
        util.assert(!this.#clientKeys.has(keyId), 'keyId (' + keyId + ') already in use');
        const privateKey = crypto.createPublicKey(keyLike);
        this.#clientKeys.set(keyId, privateKey);
    } // DAPSAgent#addClientKey

    /**
     * @param {string} keyId
     * @returns {KeyObject}
     */
    getClientKey(keyId) {
        util.assert(util.isString(keyId), 'expected keyId to be a string', TypeError);
        return this.#clientKeys.get(keyId) || null;
    } // DAPSAgent#getClientKey

    /**
     * @param {string} keyId
     * @returns {void}
     */
    removeClientKey(keyId) {
        util.assert(util.isString(keyId), 'expected keyId to be a string', TypeError);
        util.assert(this.#clientKeys.has(keyId), 'keyId (' + keyId + ') not in use');
        this.#clientKeys.delete(keyId);
    } // DAPSAgent#removeClientKey

    async getClientData(keyId) {
        // TODO
        return {
            skiaki: keyId, uri: '', securityProfile: 'BASE_SECURITY_PROFILE', extendedGuarantee: 'USAGE_CONTROL_NONE'
        };
    } // DAPSAgent#getClientData

} // DAPSAgent

module.exports = DAPSAgent;
