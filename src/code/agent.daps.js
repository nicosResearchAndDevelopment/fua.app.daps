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
        util.assert(datRequestHeader.sub, 'expected datRequestHeader.sub to be a string');

        const subject = await this.#daps.connectorCatalog.getConnectorPublicKey(datRequestHeader.sub);
        util.assert(subject, 'the subject ' + datRequestHeader.sub + ' could not be found');

        const
            subjectPublicKey      = subject.publicKey.createKeyObject(),
            verifyOptions         = {subject: subject.publicKey.keyId},
            {payload: datRequest} = await jwtVerify(datRequestToken, subjectPublicKey, verifyOptions);

        return datRequest;
    } // DAPSAgent#parseDatRequestToken

    createDatHeader(datRequest) {
        const
            // privateKey = this.#daps.privateKeys[0],
            privateKey = this.#daps.privateKeys.find(key => key.keyType === util.iri.RSA),
            datHeader  = {
                alg: 'RS256',
                typ: 'at+jwt',
                // kid: 'default'
                kid: privateKey.keyId
            };
        return datHeader;
    } // DAPSAgent#createDatHeader

    async createDatPayload(datRequest) {
        util.assert(util.isString(datRequest?.sub), 'expected datRequest.sub to be a string', TypeError);

        const subject = this.#daps.connectorCatalog.getConnectorPublicKey(datRequest.sub);
        util.assert(subject, 'the subject ' + datRequest.sub + ' could not be found');

        const
            timestamp  = util.unixTime(),
            datPayload = {
                '@context': this.#datContextURL,
                '@type':    'DatPayload',
                'iss':      this.url,
                'sub':      subject.publicKey.keyId,
                'aud':      'ALL',
                'iat':      timestamp,
                'nbf':      timestamp - 60,
                'exp':      timestamp + 60,
                /** The RDF connector entity as referred to by the DAT, with its URI included as the value. The value MUST be its accessible URI. */
                'referringConnector': subject.connector.hasEndpoint.accessURL,
                /** The SecurityProfile supported by the Connector. */
                'securityProfile': subject.connector.securityProfile,
                /** Reference to a security guarantee that, if used in combination with a security profile instance, overrides the respective guarantee of the given predefined instance. */
                'extendedGuarantee':    subject.connector.extendedGuarantees,
                'transportCertsSha256': [],
                'scope':                ['IDS_CONNECTOR_ATTRIBUTES_ALL']
            };

        return datPayload;
    } // DAPSAgent#createDatPayload

    async createDat(datHeader, datPayload) {
        const
            jwtSign        = new SignJWT(datPayload),
            dapsPrivateKey = await this.#daps.getPrivateKey(datHeader.kid),
            dat            = await jwtSign.setProtectedHeader(datHeader).sign(dapsPrivateKey.createKeyObject());

        return dat;
    } // DAPSAgent#createDat

    /**
     * @returns {Promise<{keys: Array<JsonWebKey>}>}
     */
    async generateJWKS() {
        const publicKeys = this.#daps.privateKeys.map((privateKey) => {
            const
                publicKeyObject = crypto.createPublicKey(privateKey.keyValue),
                publicJWK       = publicKeyObject.export({format: 'jwk'});
            return Object.assign({kid: privateKey.keyId}, publicJWK);
        });
        return {keys: publicKeys};
    } // DAPSAgent#generateJWKS

} // DAPSAgent

module.exports = DAPSAgent;
