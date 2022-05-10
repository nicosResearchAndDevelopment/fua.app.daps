const
    util              = require('./util.daps.js'),
    crypto            = require('crypto'),
    {Model, Resource} = require('@nrd/fua.module.space'),
    /** @type {fua.module.space.Model} */
    model             = new Model();

/**
 * @alias fua.app.daps.model.DAPS
 * @extends {fua.module.space.Resource}
 */
class DAPS extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.connectorCatalog,
            util.iri.privateKey
        ]);

        const
            connectorCatalogNode = this.node.getNode(util.iri.connectorCatalog),
            privateKeyNodeArr    = this.node.getNodes(util.iri.privateKey),
            [
                connectorCatalog,
                privateKeyArr
            ]                    = await Promise.all([
                connectorCatalogNode && model.build(connectorCatalogNode),
                Promise.all(privateKeyNodeArr.map(node => model.build(node)))
            ]);

        util.assert(connectorCatalog && (connectorCatalog instanceof ConnectorCatalog),
            `expected one ${util.iri.connectorCatalog} of type ${util.iri.ConnectorCatalog}`);
        util.assert(privateKeyArr.length && privateKeyArr.every(privateKey => privateKey instanceof PrivateKey),
            `expected ${util.iri.privateKey} of type ${util.iri.PrivateKey}`);

        this['@type']                   = this.node.type;
        this[util.iri.connectorCatalog] = connectorCatalog;
        this[util.iri.privateKey]       = privateKeyArr;

        await Promise.all([
            connectorCatalog.load(),
            Promise.all(privateKeyArr.map(privateKey => privateKey.load()))
        ]);
    } // DAPS#load

    /** @type {ConnectorCatalog | null} */
    get connectorCatalog() {
        return this[util.iri.connectorCatalog] || null;
    }

    /** @type {Array<PrivateKey>} */
    get privateKeys() {
        return this[util.iri.privateKey] || [];
    }

    /**
     * @param {string} keyId
     * @returns {PublicKey | null}
     */
    getPrivateKey(keyId) {
        return this.privateKeys.find(privateKey => privateKey.keyId === keyId) || null;
    }

} // DAPS

model.set(util.iri.DAPS, DAPS);

/**
 * @alias fua.app.daps.model.ConnectorCatalog
 * @extends {fua.module.space.Resource}
 */
class ConnectorCatalog extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.listedConnector
        ]);

        const
            listedConnectorNodeArr = this.node.getNodes(util.iri.listedConnector),
            listedConnectorArr     = await Promise.all(listedConnectorNodeArr.map(node => model.build(node)));

        util.assert(listedConnectorArr.every(listedConnector => listedConnector instanceof Connector),
            `expected ${util.iri.listedConnector} of type ${util.iri.Connector}`);

        this['@type']                  = this.node.type;
        this[util.iri.listedConnector] = listedConnectorArr;

        await Promise.all(listedConnectorArr.map(listedConnector => listedConnector.load()));
    } // ConnectorCatalog#load

    /** @type {Array<Connector>} */
    get listedConnectors() {
        return this[util.iri.listedConnector] || [];
    }

    /**
     * @param {string} keyId
     * @returns {{connector: Connector, publicKey: PublicKey} | null}
     */
    getConnectorPublicKey(keyId) {
        for (let connector of this.listedConnectors) {
            const publicKey = connector.getPublicKey(keyId);
            if (publicKey) return {connector, publicKey};
        }
        return null;
    }

} // ConnectorCatalog

model.set(util.iri.ConnectorCatalog, ConnectorCatalog);

/**
 * @alias fua.app.daps.model.Connector
 * @extends {fua.module.space.Resource}
 */
class Connector extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.securityProfile,
            util.iri.extendedGuarantee,
            util.iri.authInfo,
            util.iri.hasEndpoint,
            util.iri.publicKey
        ]);

        const
            securityProfileNode      = this.node.getNode(util.iri.securityProfile),
            extendedGuaranteeNodeArr = this.node.getNodes(util.iri.extendedGuarantee),
            publicKeyNodeArr         = this.node.getNodes(util.iri.publicKey),
            // authInfoNode             = this.node.getNode(util.iri.authInfo),
            hasEndpointNode          = this.node.getNode(util.iri.hasEndpoint),
            // hasDefaultEndpointNode   = this.node.getNode(util.iri.hasDefaultEndpoint),
            [
                // securityProfile,
                // extendedGuaranteeArr,
                hasEndpoint,
                publicKeyArr
            ]                        = await Promise.all([
                // securityProfileNode && model.build(securityProfileNode),
                // Promise.all(extendedGuaranteeArr.map(node => model.build(node))),
                hasEndpointNode && model.build(hasEndpointNode),
                Promise.all(publicKeyNodeArr.map(node => model.build(node)))
            ]);

        // util.assert(securityProfile && (securityProfile instanceof SecurityProfile),
        //     `expected one ${util.iri.securityProfile} of type ${util.iri.SecurityProfile}`);
        util.assert(securityProfileNode,
            `expected one ${util.iri.securityProfile}`);
        util.assert(hasEndpoint && (hasEndpoint instanceof ConnectorEndpoint),
            `expected one ${util.iri.hasEndpoint} of type ${util.iri.ConnectorEndpoint}`);
        // util.assert(extendedGuaranteeArr.every(extendedGuarantee => extendedGuarantee instanceof SecurityGuarantee),
        //     `expected ${util.iri.extendedGuarantee} of type ${util.iri.SecurityGuarantee}`);
        util.assert(publicKeyArr.every(publicKey => publicKey instanceof PublicKey),
            `expected ${util.iri.publicKey} of type ${util.iri.PublicKey}`);

        this['@type']                    = this.node.type;
        this[util.iri.securityProfile]   = securityProfileNode.id;
        this[util.iri.extendedGuarantee] = extendedGuaranteeNodeArr.map(extendedGuaranteeNode => extendedGuaranteeNode.id);
        // this[util.iri.authInfo]           = authInfo;
        this[util.iri.hasEndpoint]       = hasEndpoint;
        // this[util.iri.hasDefaultEndpoint] = hasDefaultEndpoint;
        this[util.iri.publicKey]         = publicKeyArr;

        await Promise.all([
            hasEndpoint.load(),
            Promise.all(publicKeyArr.map(publicKey => publicKey.load()))
        ]);
    } // Connector#load

    /** @type {SecurityProfile} */
    get securityProfile() {
        return this[util.iri.securityProfile] || '';
    }

    /** @type {Array<SecurityGuarantee>} */
    get extendedGuarantees() {
        return this[util.iri.extendedGuarantee] || [];
    }

    /** @type {ConnectorEndpoint} */
    get hasEndpoint() {
        return this[util.iri.hasEndpoint] || null;
    }

    /** @type {Array<PublicKey>} */
    get publicKeys() {
        return this[util.iri.publicKey] || [];
    }

    /**
     * @param {string} keyId
     * @returns {PublicKey | null}
     */
    getPublicKey(keyId) {
        return this.publicKeys.find(privateKey => privateKey.keyId === keyId) || null;
    }

} // Connector

model.set(util.iri.Connector, Connector);

/**
 * @alias fua.app.daps.model.CryptoKey
 * @extends {fua.module.space.Resource}
 */
class CryptoKey extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.keyId,
            util.iri.keyType,
            util.iri.keyValue
        ]);

        const
            keyIdLiteral    = this.node.getLiteral(util.iri.keyId),
            keyTypeNode     = this.node.getNode(util.iri.keyType),
            keyValueLiteral = this.node.getLiteral(util.iri.keyValue);

        util.assert(keyIdLiteral,
            `expected one ${util.iri.keyId}`);
        util.assert(keyTypeNode,
            `expected one ${util.iri.keyType}`);
        util.assert(keyValueLiteral,
            `expected one ${util.iri.keyValue}`);

        this['@type']           = this.node.type;
        this[util.iri.keyId]    = keyIdLiteral.valueOf();
        this[util.iri.keyType]  = keyTypeNode.id;
        this[util.iri.keyValue] = keyValueLiteral.valueOf();
    } // CryptoKey#load

    /** @type {string} */
    get keyId() {
        return this[util.iri.keyId] || '';
    }

    /** @type {string} */
    get keyType() {
        return this[util.iri.keyType] || '';
    }

    /** @type {Buffer | string} */
    get keyValue() {
        return this[util.iri.keyValue] || '';
    }

} // CryptoKey

/**
 * @alias fua.app.daps.model.PublicKey
 * @extends {fua.app.daps.model.CryptoKey}
 */
class PublicKey extends CryptoKey {

    /** @returns {import("crypto").KeyObject} */
    createKeyObject() {
        return crypto.createPublicKey(this.keyValue);
    } // PublicKey#createKeyObject

} // PublicKey

/**
 * @alias fua.app.daps.model.PrivateKey
 * @extends {fua.app.daps.model.CryptoKey}
 */
class PrivateKey extends CryptoKey {

    /** @returns {import("crypto").KeyObject} */
    createKeyObject() {
        return crypto.createPrivateKey(this.keyValue);
    } // PrivateKey#createKeyObject

} // PrivateKey

model.set(util.iri.PublicKey, PublicKey);
model.set(util.iri.PrivateKey, PrivateKey);

/**
 * @alias fua.app.daps.model.AuthInfo
 * @extends {fua.module.space.Resource}
 */
class AuthInfo extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.authService,
            util.iri.authStandard
        ]);

        const
            authServiceNode  = this.node.getNode(util.iri.authService),
            authStandardNode = this.node.getNode(util.iri.authStandard);

        util.assert(authServiceNode,
            `expected one ${util.iri.authService}`);
        util.assert(authStandardNode,
            `expected one ${util.iri.authStandard}`);

        this['@type']               = this.node.type;
        this[util.iri.authService]  = authServiceNode.id;
        this[util.iri.authStandard] = authStandardNode.id;
    } // AuthInfo#load

    /** @type {string} */
    get authService() {
        return this[util.iri.authService] || '';
    }

    /** @type {string} */
    get authStandard() {
        return this[util.iri.authStandard] || '';
    }

} // AuthInfo

model.set(util.iri.AuthInfo, AuthInfo);

/**
 * @alias fua.app.daps.model.ConnectorEndpoint
 * @extends {fua.module.space.Resource}
 */
class ConnectorEndpoint extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.accessURL
        ]);

        const
            accessURLLiteral = this.node.getLiteral(util.iri.accessURL);

        util.assert(accessURLLiteral,
            `expected one ${util.iri.accessURL}`);

        this['@type']            = this.node.type;
        this[util.iri.accessURL] = accessURLLiteral.valueOf();
    } // ConnectorEndpoint#load

    /** @type {string} */
    get accessURL() {
        return this[util.iri.accessURL] || '';
    }

} // ConnectorEndpoint

model.set(util.iri.ConnectorEndpoint, ConnectorEndpoint);

/**
 * @alias fua.app.daps.model.SecurityProfile
 * @extends {fua.module.space.Resource}
 */
class SecurityProfile extends Resource {

    async load() {
        await this.node.load([
            '@type'
        ]);

        this['@type'] = this.node.type;
    } // SecurityProfile#load

} // SecurityProfile

model.set(util.iri.SecurityProfile, SecurityProfile);

/**
 * @alias fua.app.daps.model.SecurityGuarantee
 * @extends {fua.module.space.Resource}
 */
class SecurityGuarantee extends Resource {

    async load() {
        await this.node.load([
            '@type'
        ]);

        this['@type'] = this.node.type;
    } // SecurityGuarantee#load

} // SecurityGuarantee

model.set(util.iri.SecurityGuarantee, SecurityGuarantee);

module.exports = model.finish();
