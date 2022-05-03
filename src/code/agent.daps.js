const
    path        = require('path'),
    crypto      = require('crypto'),
    util        = require('./util.daps.js'),
    ServerAgent = require('@nrd/fua.agent.server'),
    jose        = require('@nrd/fua.module.jose'),
    express     = require('express');

/** @see https://github.com/International-Data-Spaces-Association/IDS-G/tree/master/core/DAPS */
async function DAPSMiddleware() {

    // REM this is just a draft of a DAT-Response with very limited options
    // REM based on: https://git02.int.nsc.ag/spetrac/idsa-infomodel/-/tree/master/daps

    const
        certs              = {
            client: require('../../cert/connector/client.js'),
            server: require('../../cert/tls-server/server.js')
        },
        route              = express.Router(),
        express_json       = express.json(),
        express_urlencoded = express.urlencoded({extended: false}),
        //{publicKey, privateKey} = await AgentJOSE.JWK.generateKeyPair({algorithm: 'PS256', keySize: 4096}),
        publicKey          = crypto.createPublicKey(certs.server.pub),
        privateKey         = crypto.createPrivateKey(certs.server.key),
        publicJWK          = await AgentJOSE.JWK.serialize(publicKey),
        connectorStore     = new Map(),
        addConnector       = (connector) => connectorStore.set(`${connector.ski}:keyid:${connector.aki}`, connector);

    //gbx_daps.addServerKey('default', certs.server.key);
    //gbx_daps.addClientKey('DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A:keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8', certs.client.pub);

    addConnector({
        ski:               'DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A',
        aki:               'CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8',
        uri:               'https://localhost:8081',
        publicKey:         certs.client.pub,
        securityProfile:   "ids:BASE_CONNECTOR_SECURITY_PROFILE",
        extendedGuarantee: "idsc:USAGE_CONTROL_POLICY_ENFORCEMENT"
    });

    /**
     * @see https://datatracker.ietf.org/doc/html/rfc7517 JSON Web Key (JWK)
     * @see https://github.com/panva/jose/blob/cdce59a340b87b681a003ca28a9116c1f11d3f12/docs/functions/jwks_remote.createremotejwkset.md Function: createRemoteJWKSet
     * @see https://auth0.com/docs/tokens/json-web-tokens/json-web-key-set-properties JSON Web Key Set Properties
     * @see https://www.googleapis.com/oauth2/v3/certs Example: Google OAuth2
     */
    route.get('/.well-known/jwks.json', (request, response) => {
        response.type('json').send(JSON.stringify({
            keys: [publicJWK]
        }, null, 2));
    });

    route.post('/token', express_json, express_urlencoded, async (request, response, next) => {
        try {
            util.assert(request.body, 'Payload must be json or urlencoded.');
            const {grant_type, client_assertion_type, scope, client_assertion} = request.body;
            util.assert(grant_type === 'client_credentials', 'grant_type must be "client_credentials"');
            util.assert(client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwtbearer',
                'client_assertion_type must be "urn:ietf:params:oauth:client-assertion-type:jwtbearer"');
            // TODO handle scope differently
            util.assert(scope === 'idsc:IDS_CONNECTOR_ATTRIBUTES_ALL', 'scope must be "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL"');
            util.assert(util.isString(client_assertion), 'client_assertion must be a string');
            const assertionHeader = await AgentJOSE.JWT.decodeHeader(client_assertion);
            util.assert(assertionHeader.sub && connectorStore.has(assertionHeader.sub), 'The client_assertion header must contain a registered subject.');
            const
                subject                 = connectorStore.get(assertionHeader.sub),
                subjectPublicKey        = crypto.createPublicKey(subject.publicKey),
                {payload: tokenRequest} = await AgentJOSE.JWT.verify(client_assertion, subjectPublicKey),
                timestamp               = util.unixTime(),
                dynAttrToken            = await AgentJOSE.JWT.sign({
                    '@context':             'https://w3id.org/idsa/contexts/context.jsonld',
                    '@type':                'ids:DatPayload',
                    'iss':                  request.protocol + '://' + request.hostname + '/',
                    'sub':                  tokenRequest.sub,
                    'aud':                  'idsc:IDS_CONNECTORS_ALL',
                    'iat':                  timestamp,
                    'nbf':                  timestamp - 60,
                    'exp':                  timestamp + 60,
                    'referringConnector':   subject.uri,
                    'securityProfile':      subject.securityProfile,
                    'extendedGuarantee':    subject.extendedGuarantee,
                    'transportCertsSha256': [],
                    'scope':                ["idsc:IDS_CONNECTOR_ATTRIBUTES_ALL", "idsc:ids_connector_attributes"]
                }, privateKey, {algorithm: 'RS256'});

            response.type('json').send(JSON.stringify({
                alg:          'RS256',
                typ:          'JWT',
                kid:          'default',
                access_token: dynAttrToken,
                signature:    null
            }));
        } catch (err) {
            next(err);
        }
    });

    // TODO

    return route;

} // DAPSMiddleware

class DAPSAgent extends ServerAgent {

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

    // TODO

} // DAPSAgent

module.exports = DAPSAgent;
