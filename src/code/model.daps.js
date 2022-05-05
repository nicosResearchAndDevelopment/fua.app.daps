const
    util               = require('./util.daps.js'),
    crypto             = require('crypto'),
    {Model, Resource}  = require('@nrd/fua.module.space'),
    {serializeDataset} = require('@nrd/fua.module.rdf'),
    /** @type {fua.module.space.Model} */
    model              = new Model();

model.set(util.iri.DAPS, class DAPS extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.connectorCatalog
        ]);

        const
            connectorCatalog = this.node.getNode(util.iri.connectorCatalog);

        this['@type']                   = this.node.type;
        this[util.iri.connectorCatalog] = connectorCatalog ? await model.build(connectorCatalog) : null;

        if (this[util.iri.connectorCatalog]) await this[util.iri.connectorCatalog].load();
    } // DAPS#load

    async save() {
        this.node.type = this['@type'];

        if (this[util.iri.connectorCatalog])
            this.node.setNode(util.iri.connectorCatalog, this[util.iri.connectorCatalog]);
        else this.node.deleteNode(util.iri.connectorCatalog);

        await this.node.save([
            '@type',
            util.iri.connectorCatalog
        ]);

        if (this[util.iri.connectorCatalog]) await this[util.iri.connectorCatalog].save();
    } // DAPS#save

    async serialize(contentType = 'text/turtle') {
        const dataset = this.node.dataset();
        return await serializeDataset(dataset, contentType);
    } // DAPS#serialize

    get connectorCatalog() {
        return this[util.iri.connectorCatalog] || null;
    }

}); // DAPS

model.set(util.iri.ConnectorCatalog, class ConnectorCatalog extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.listedConnector
        ]);

        const
            listedConnector = this.node.getNodes(util.iri.listedConnector);

        this['@type']                  = this.node.type;
        this[util.iri.listedConnector] = await Promise.all(listedConnector.map(node => model.build(node)));
    } // ConnectorCatalog#load

    async save() {
        this.node.type = this['@type'];

        if (this[util.iri.listedConnector] && this[util.iri.listedConnector].length > 0)
            this.node.setNodes(util.iri.listedConnector, this[util.iri.listedConnector]);
        else this.node.deleteNodes(util.iri.listedConnector);

        await this.node.save([
            '@type',
            util.iri.listedConnector
        ]);
    } // ConnectorCatalog#save

    async serialize(contentType = 'text/turtle') {
        const dataset = this.node.dataset();
        return await serializeDataset(dataset, contentType);
    } // ConnectorCatalog#serialize

    async findConnector(keyId) {
        if (this[util.iri.listedConnector]) for (let connector of this[util.iri.listedConnector]) {
            if (!connector.publicKey) await connector.load();
            if (connector.publicKey.keyId === keyId) return connector;
        }
        return null;
    } // ConnectorCatalog#findConnector

}); // ConnectorCatalog

model.set(util.iri.Connector, class Connector extends Resource {

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
            securityProfile   = this.node.getNode(util.iri.securityProfile),
            extendedGuarantee = this.node.getNodes(util.iri.extendedGuarantee),
            authInfo          = this.node.getNode(util.iri.authInfo),
            hasEndpoint       = this.node.getNode(util.iri.hasEndpoint),
            publicKey         = this.node.getNode(util.iri.publicKey);

        this['@type']                    = this.node.type;
        this[util.iri.securityProfile]   = securityProfile ? await model.build(securityProfile) : null;
        this[util.iri.extendedGuarantee] = await Promise.all(extendedGuarantee.map(node => model.build(node)));
        this[util.iri.authInfo]          = authInfo ? await model.build(authInfo) : null;
        this[util.iri.hasEndpoint]       = hasEndpoint ? await model.build(hasEndpoint) : null;
        this[util.iri.publicKey]         = publicKey ? await model.build(publicKey) : null;

        if (this[util.iri.authInfo]) await this[util.iri.authInfo].load();
        if (this[util.iri.hasEndpoint]) await this[util.iri.hasEndpoint].load();
        if (this[util.iri.publicKey]) await this[util.iri.publicKey].load();
    } // Connector#load

    async save() {
        this.node.type = this['@type'];

        if (this[util.iri.securityProfile])
            this.node.setNode(util.iri.securityProfile, this[util.iri.securityProfile]);
        else this.node.deleteNode(util.iri.securityProfile);

        if (this[util.iri.extendedGuarantee] && this[util.iri.extendedGuarantee].length > 0)
            this.node.setNodes(util.iri.extendedGuarantee, this[util.iri.extendedGuarantee]);
        else this.node.deleteNodes(util.iri.extendedGuarantee);

        if (this[util.iri.authInfo])
            this.node.setNode(util.iri.authInfo, this[util.iri.authInfo]);
        else this.node.deleteNode(util.iri.authInfo);

        if (this[util.iri.hasEndpoint])
            this.node.setNode(util.iri.hasEndpoint, this[util.iri.hasEndpoint]);
        else this.node.deleteNode(util.iri.hasEndpoint);

        if (this[util.iri.publicKey])
            this.node.setNode(util.iri.publicKey, this[util.iri.publicKey]);
        else this.node.deleteNode(util.iri.publicKey);

        await this.node.save([
            '@type',
            util.iri.securityProfile,
            util.iri.extendedGuarantee,
            util.iri.authInfo,
            util.iri.hasEndpoint,
            util.iri.publicKey
        ]);

        if (this[util.iri.authInfo]) await this[util.iri.authInfo].save();
        if (this[util.iri.hasEndpoint]) await this[util.iri.hasEndpoint].save();
        if (this[util.iri.publicKey]) await this[util.iri.publicKey].save();
    } // Connector#save

    async serialize(contentType = 'text/turtle') {
        const dataset = this.node.dataset();
        return await serializeDataset(dataset, contentType);
    } // Connector#serialize

    get securityProfile() {
        return this[util.iri.securityProfile]?.node.id || null;
    }

    get extendedGuarantee() {
        return this[util.iri.extendedGuarantee]?.map(res => res.node.id) || null;
    }

    get authInfo() {
        return this[util.iri.authInfo] || null;
    }

    get hasEndpoint() {
        return this[util.iri.hasEndpoint] || null;
    }

    get publicKey() {
        return this[util.iri.publicKey] || null;
    }

}); // Connector

model.set(util.iri.PublicKey, class PublicKey extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.keyId,
            util.iri.keyType,
            util.iri.keyValue
        ]);

        const
            keyId    = this.node.getLiteral(util.iri.keyId),
            keyType  = this.node.getNode(util.iri.keyType),
            keyValue = this.node.getLiteral(util.iri.keyValue);

        this['@type']           = this.node.type;
        this[util.iri.keyId]    = keyId ? keyId : null;
        this[util.iri.keyType]  = keyType ? await model.build(keyType) : null;
        this[util.iri.keyValue] = keyValue ? keyValue : null;
    } // PublicKey#load

    async save() {
        this.node.type = this['@type'];

        if (this[util.iri.keyId])
            this.node.setLiteral(util.iri.keyId, this[util.iri.keyId]);
        else this.node.deleteLiteral(util.iri.keyId);

        if (this[util.iri.keyType])
            this.node.setNode(util.iri.keyType, this[util.iri.keyType]);
        else this.node.deleteNode(util.iri.keyType);

        if (this[util.iri.keyValue])
            this.node.setLiteral(util.iri.keyValue, this[util.iri.keyValue]);
        else this.node.deleteLiteral(util.iri.keyValue);

        await this.node.save([
            '@type',
            util.iri.keyId,
            util.iri.keyType,
            util.iri.keyValue
        ]);
    } // PublicKey#save

    async serialize(contentType = 'text/turtle') {
        const dataset = this.node.dataset();
        return await serializeDataset(dataset, contentType);
    } // PublicKey#serialize

    get keyId() {
        return this[util.iri.keyId]?.valueOf() || null;
    }

    get keyType() {
        return this[util.iri.keyType]?.node.id || null;
    }

    get keyValue() {
        return this[util.iri.keyValue]?.valueOf() || null;
    }

    createKeyObject() {
        const keyValue = this.keyValue;
        util.assert(util.isBuffer(keyValue), 'expected keyValue to contain binary data');
        return crypto.createPublicKey(keyValue);
    }

}); // PublicKey

model.set(util.iri.AuthInfo, class AuthInfo extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.authService,
            util.iri.authStandard
        ]);

        const
            authService  = this.node.getNode(util.iri.authService),
            authStandard = this.node.getNode(util.iri.authStandard);

        this['@type']               = this.node.type;
        this[util.iri.authService]  = authService ? await model.build(authService) : null;
        this[util.iri.authStandard] = authStandard ? await model.build(authStandard) : null;
    } // AuthInfo#load

    async save() {
        this.node.type = this['@type'];

        if (this[util.iri.authService])
            this.node.setNode(util.iri.authService, this[util.iri.authService]);
        else this.node.deleteNode(util.iri.authService);

        if (this[util.iri.authStandard])
            this.node.setNode(util.iri.authStandard, this[util.iri.authStandard]);
        else this.node.deleteNode(util.iri.authStandard);

        await this.node.save([
            '@type',
            util.iri.authService,
            util.iri.authStandard
        ]);
    } // AuthInfo#save

    async serialize(contentType = 'text/turtle') {
        const dataset = this.node.dataset();
        return await serializeDataset(dataset, contentType);
    } // AuthInfo#serialize

    get authService() {
        return this[util.iri.authService]?.node.id || null;
    }

    get authStandard() {
        return this[util.iri.authStandard]?.node.id || null;
    }

}); // AuthInfo

model.set(util.iri.ConnectorEndpoint, class ConnectorEndpoint extends Resource {

    async load() {
        await this.node.load([
            '@type',
            util.iri.accessURL
        ]);

        const
            accessURL = this.node.getLiteral(util.iri.accessURL);

        this['@type']            = this.node.type;
        this[util.iri.accessURL] = accessURL ? accessURL : null;
    } // ConnectorEndpoint#load

    async save() {
        this.node.type = this['@type'];

        if (this[util.iri.accessURL])
            this.node.setLiteral(util.iri.accessURL, this[util.iri.accessURL]);
        else this.node.deleteLiteral(util.iri.accessURL);

        await this.node.save([
            '@type',
            util.iri.accessURL
        ]);
    } // ConnectorEndpoint#save

    async serialize(contentType = 'text/turtle') {
        const dataset = this.node.dataset();
        return await serializeDataset(dataset, contentType);
    } // ConnectorEndpoint#serialize

    get accessURL() {
        return this[util.iri.accessURL]?.valueOf() || null;
    }

}); // ConnectorEndpoint

module.exports = model.finish();
