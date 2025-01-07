const
    assert            = require('@fua/core.assert'),
    crypto            = require('crypto'),
    {Model, Resource} = require('@fua/module.space'),
    /** @type {fua.module.space.Model} */
    model             = new Model(),
    IRI               = Object.freeze({
        type: 'rdf:type',

        DAPS:                 'ids:DAPS',
        ConnectorCatalog:     'ids:ConnectorCatalog',
        Connector:            'ids:Connector',
        SecurityProfile:      'ids:SecurityProfile',
        SecurityGuarantee:    'ids:SecurityGuarantee',
        PublicKey:            'ids:PublicKey',
        Endpoint:             'ids:Endpoint',
        ConnectorEndpoint:    'ids:ConnectorEndpoint',
        AuthInfo:             'ids:AuthInfo',
        connectorCatalog:     'ids:connectorCatalog',
        listedConnector:      'ids:listedConnector',
        securityProfile:      'ids:securityProfile',
        extendedGuarantee:    'ids:extendedGuarantee',
        transportCertsSha256: 'ids:transportCertsSha256',
        publicKey:            'ids:publicKey',
        keyType:              'ids:keyType',
        keyValue:             'ids:keyValue',
        hasEndpoint:          'ids:hasEndpoint',
        hasDefaultEndpoint:   'ids:hasDefaultEndpoint',
        accessURL:            'ids:accessURL',
        authInfo:             'ids:authInfo',
        authService:          'ids:authService',
        authStandard:         'ids:authStandard',

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

/**
 * @alias fua.app.daps.model.DAPS
 * @extends {fua.module.space.Resource}
 */
class DAPS extends Resource {

    async load() {
        await this.node.load([
            '@type',
            IRI.connectorCatalog,
            IRI.privateKey
        ]);

        const
            connectorCatalogNode = this.node.getNode(IRI.connectorCatalog),
            privateKeyNodeArr    = this.node.getNodes(IRI.privateKey),
            [
                connectorCatalog,
                privateKeyArr
            ]                    = await Promise.all([
                connectorCatalogNode && model.build(connectorCatalogNode),
                Promise.all(privateKeyNodeArr.map(node => model.build(node)))
            ]);

        assert(connectorCatalog && (connectorCatalog instanceof ConnectorCatalog),
            `expected one ${IRI.connectorCatalog} of type ${IRI.ConnectorCatalog}`);
        assert(privateKeyArr.length && privateKeyArr.every(privateKey => privateKey instanceof PrivateKey),
            `expected ${IRI.privateKey} of type ${IRI.PrivateKey}`);

        this['@type']              = this.node.type;
        this[IRI.connectorCatalog] = connectorCatalog;
        this[IRI.privateKey]       = privateKeyArr;

        await Promise.all([
            connectorCatalog.load(),
            Promise.all(privateKeyArr.map(privateKey => privateKey.load()))
        ]);
    } // DAPS#load

    /** @type {ConnectorCatalog | null} */
    get connectorCatalog() {
        return this[IRI.connectorCatalog] || null;
    }

    /** @type {Array<PrivateKey>} */
    get privateKeys() {
        return this[IRI.privateKey] || [];
    }

    /**
     * @returns {import("agent.daps").JsonWebKeySet}
     */
    createJWKS() {
        return {keys: this.privateKeys.map(privateKey => privateKey.createJWK())};
    }

    /**
     * @param {string} keyId
     * @returns {PublicKey | null}
     */
    getPrivateKey(keyId) {
        return this.privateKeys.find(privateKey => privateKey.keyId === keyId) || null;
    }

    async addPrivateKey(keyId, keyType, keyValue) {
        assert(false, 'not implemented'); // TODO
    } // DAPS#addPrivateKey

    async removePrivateKey(keyId, keyType, keyValue) {
        assert(false, 'not implemented'); // TODO
    } // DAPS#removePrivateKey

} // DAPS

model.set(IRI.DAPS, DAPS);

/**
 * @alias fua.app.daps.model.ConnectorCatalog
 * @extends {fua.module.space.Resource}
 */
class ConnectorCatalog extends Resource {

    async load() {
        await this.node.load([
            '@type',
            IRI.listedConnector
        ]);

        const
            listedConnectorNodeArr = this.node.getNodes(IRI.listedConnector),
            listedConnectorArr     = await Promise.all(listedConnectorNodeArr.map(node => model.build(node)));

        assert(listedConnectorArr.every(listedConnector => listedConnector instanceof Connector),
            `expected ${IRI.listedConnector} of type ${IRI.Connector}`);

        this['@type']             = this.node.type;
        this[IRI.listedConnector] = listedConnectorArr;

        await Promise.all(listedConnectorArr.map(listedConnector => listedConnector.load()));
    } // ConnectorCatalog#load

    /** @type {Array<Connector>} */
    get listedConnectors() {
        return this[IRI.listedConnector] || [];
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

    async addConnector(/* TODO */) {
        assert(false, 'not implemented'); // TODO
    } // ConnectorCatalog#addConnector

    async removeConnector(/* TODO */) {
        assert(false, 'not implemented'); // TODO
    } // ConnectorCatalog#removeConnector

} // ConnectorCatalog

model.set(IRI.ConnectorCatalog, ConnectorCatalog);

/**
 * @alias fua.app.daps.model.Connector
 * @extends {fua.module.space.Resource}
 */
class Connector extends Resource {

    async load() {
        await this.node.load([
            '@type',
            IRI.securityProfile,
            IRI.extendedGuarantee,
            IRI.transportCertsSha256,
            IRI.authInfo,
            IRI.hasEndpoint,
            IRI.publicKey
        ]);

        const
            securityProfileNode            = this.node.getNode(IRI.securityProfile),
            extendedGuaranteeNodeArr       = this.node.getNodes(IRI.extendedGuarantee),
            transportCertsSha256LiteralArr = this.node.getLiterals(IRI.transportCertsSha256),
            publicKeyNodeArr               = this.node.getNodes(IRI.publicKey),
            // authInfoNode             = this.node.getNode(IRI.authInfo),
            hasEndpointNode                = this.node.getNode(IRI.hasEndpoint),
            // hasDefaultEndpointNode   = this.node.getNode(IRI.hasDefaultEndpoint),
            [
                // securityProfile,
                // extendedGuaranteeArr,
                hasEndpoint,
                publicKeyArr
            ]                              = await Promise.all([
                // securityProfileNode && model.build(securityProfileNode),
                // Promise.all(extendedGuaranteeArr.map(node => model.build(node))),
                hasEndpointNode && model.build(hasEndpointNode),
                Promise.all(publicKeyNodeArr.map(node => model.build(node)))
            ]);

        // assert(securityProfile && (securityProfile instanceof SecurityProfile),
        //     `expected one ${IRI.securityProfile} of type ${IRI.SecurityProfile}`);
        assert(securityProfileNode,
            `expected one ${IRI.securityProfile}`);
        assert(hasEndpoint && (hasEndpoint instanceof ConnectorEndpoint),
            `expected one ${IRI.hasEndpoint} of type ${IRI.ConnectorEndpoint}`);
        // assert(extendedGuaranteeArr.every(extendedGuarantee => extendedGuarantee instanceof SecurityGuarantee),
        //     `expected ${IRI.extendedGuarantee} of type ${IRI.SecurityGuarantee}`);
        assert(publicKeyArr.every(publicKey => publicKey instanceof PublicKey),
            `expected ${IRI.publicKey} of type ${IRI.PublicKey}`);

        this['@type']                  = this.node.type;
        this[IRI.securityProfile]      = securityProfileNode.id;
        this[IRI.extendedGuarantee]    = extendedGuaranteeNodeArr.map(extendedGuaranteeNode => extendedGuaranteeNode.id);
        this[IRI.transportCertsSha256] = transportCertsSha256LiteralArr.map(transportCertsSha256Literal => transportCertsSha256Literal.value);
        // this[IRI.authInfo]           = authInfo;
        this[IRI.hasEndpoint]          = hasEndpoint;
        // this[IRI.hasDefaultEndpoint] = hasDefaultEndpoint;
        this[IRI.publicKey]            = publicKeyArr;

        await Promise.all([
            hasEndpoint.load(),
            Promise.all(publicKeyArr.map(publicKey => publicKey.load()))
        ]);
    } // Connector#load

    /** @type {SecurityProfile} */
    get securityProfile() {
        return this[IRI.securityProfile] || '';
    }

    /** @type {Array<SecurityGuarantee>} */
    get extendedGuarantees() {
        return this[IRI.extendedGuarantee] || [];
    }

    /** @type {Array<string>} */
    get transportCertsSha256() {
        return this[IRI.transportCertsSha256] || [];
    }

    /** @type {ConnectorEndpoint} */
    get hasEndpoint() {
        return this[IRI.hasEndpoint] || null;
    }

    /** @type {Array<PublicKey>} */
    get publicKeys() {
        return this[IRI.publicKey] || [];
    }

    /**
     * @param {string} keyId
     * @returns {PublicKey | null}
     */
    getPublicKey(keyId) {
        return this.publicKeys.find(privateKey => privateKey.keyId === keyId) || null;
    } // Connector#getPublicKey

    async addPublicKey(keyId, keyType, keyValue) {
        assert(false, 'not implemented'); // TODO
    } // Connector#addPublicKey

    async removePublicKey(keyId) {
        assert(false, 'not implemented'); // TODO
    } // Connector#removePublicKey

} // Connector

model.set(IRI.Connector, Connector);

/**
 * @alias fua.app.daps.model.CryptoKey
 * @extends {fua.module.space.Resource}
 */
class CryptoKey extends Resource {

    async load() {
        await this.node.load([
            '@type',
            IRI.keyId,
            IRI.keyType,
            IRI.keyValue
        ]);

        const
            keyIdLiteral    = this.node.getLiteral(IRI.keyId),
            keyTypeNode     = this.node.getNode(IRI.keyType),
            keyValueLiteral = this.node.getLiteral(IRI.keyValue);

        assert(keyIdLiteral,
            `expected one ${IRI.keyId}`);
        assert(keyTypeNode,
            `expected one ${IRI.keyType}`);
        assert(keyValueLiteral,
            `expected one ${IRI.keyValue}`);

        this['@type']      = this.node.type;
        this[IRI.keyId]    = keyIdLiteral.valueOf();
        this[IRI.keyType]  = keyTypeNode.id;
        this[IRI.keyValue] = keyValueLiteral.valueOf();
    } // CryptoKey#load

    /** @type {string} */
    get keyId() {
        return this[IRI.keyId] || '';
    }

    /** @type {string} */
    get keyType() {
        return this[IRI.keyType] || '';
    }

    /** @type {Buffer | string} */
    get keyValue() {
        return this[IRI.keyValue] || '';
    }

    /** @returns {import("agent.daps").JsonWebKey} */
    createJWK() {
        const publicKeyObject = crypto.createPublicKey(this.keyValue);
        return Object.assign({kid: this.keyId}, publicKeyObject.export({format: 'jwk'}));
    } // CryptoKey#createJWK

} // CryptoKey

/**
 * @alias fua.app.daps.model.PublicKey
 * @extends {fua.app.daps.model.CryptoKey}
 */
class PublicKey extends CryptoKey {

    /** @returns {import("agent.daps").KeyObject} */
    createKeyObject() {
        return crypto.createPublicKey(this.keyValue);
    } // PublicKey#createKeyObject

} // PublicKey

/**
 * @alias fua.app.daps.model.PrivateKey
 * @extends {fua.app.daps.model.CryptoKey}
 */
class PrivateKey extends CryptoKey {

    /** @returns {import("agent.daps").KeyObject} */
    createKeyObject() {
        return crypto.createPrivateKey(this.keyValue);
    } // PrivateKey#createKeyObject

} // PrivateKey

model.set(IRI.PublicKey, PublicKey);
model.set(IRI.PrivateKey, PrivateKey);

/**
 * @alias fua.app.daps.model.AuthInfo
 * @extends {fua.module.space.Resource}
 */
class AuthInfo extends Resource {

    async load() {
        await this.node.load([
            '@type',
            IRI.authService,
            IRI.authStandard
        ]);

        const
            authServiceNode  = this.node.getNode(IRI.authService),
            authStandardNode = this.node.getNode(IRI.authStandard);

        assert(authServiceNode,
            `expected one ${IRI.authService}`);
        assert(authStandardNode,
            `expected one ${IRI.authStandard}`);

        this['@type']          = this.node.type;
        this[IRI.authService]  = authServiceNode.id;
        this[IRI.authStandard] = authStandardNode.id;
    } // AuthInfo#load

    /** @type {string} */
    get authService() {
        return this[IRI.authService] || '';
    }

    /** @type {string} */
    get authStandard() {
        return this[IRI.authStandard] || '';
    }

} // AuthInfo

model.set(IRI.AuthInfo, AuthInfo);

/**
 * @alias fua.app.daps.model.ConnectorEndpoint
 * @extends {fua.module.space.Resource}
 */
class ConnectorEndpoint extends Resource {

    async load() {
        await this.node.load([
            '@type',
            IRI.accessURL
        ]);

        const
            accessURLLiteral = this.node.getLiteral(IRI.accessURL);

        assert(accessURLLiteral,
            `expected one ${IRI.accessURL}`);

        this['@type']       = this.node.type;
        this[IRI.accessURL] = accessURLLiteral.valueOf();
    } // ConnectorEndpoint#load

    /** @type {string} */
    get accessURL() {
        return this[IRI.accessURL] || '';
    }

} // ConnectorEndpoint

model.set(IRI.ConnectorEndpoint, ConnectorEndpoint);

/**
 * @alias fua.app.daps.model.SecurityProfile
 * @extends {fua.module.space.Resource}
 */
class SecurityProfile extends Resource {

    async load() {
        // await this.node.load([
        //     '@type'
        // ]);
        //
        // this['@type'] = this.node.type;
    } // SecurityProfile#load

} // SecurityProfile

model.set(IRI.SecurityProfile, SecurityProfile);

/**
 * @alias fua.app.daps.model.SecurityGuarantee
 * @extends {fua.module.space.Resource}
 */
class SecurityGuarantee extends Resource {

    async load() {
        // await this.node.load([
        //     '@type'
        // ]);
        //
        // this['@type'] = this.node.type;
    } // SecurityGuarantee#load

} // SecurityGuarantee

model.set(IRI.SecurityGuarantee, SecurityGuarantee);

module.exports = model.finish();
