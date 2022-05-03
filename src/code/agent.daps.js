const
    path        = require('path'),
    crypto      = require('crypto'),
    util        = require('./util.daps.js'),
    ServerAgent = require('@nrd/fua.agent.server'),
    jose        = require('@nrd/fua.module.jose');

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
