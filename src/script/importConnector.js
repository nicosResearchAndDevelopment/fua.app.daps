const
    path       = require('path'),
    fs         = require('fs/promises'),
    ca_testbed = path.join(__dirname, '../../../..', 'script/ca', 'resources/nrd-testbed'),
    daps_data  = path.join(__dirname, '../..', 'data'),
    config     = {
        baseURL:      'https://daps.tb.nicos-rd.com/',
        skipAll:      false,
        overwriteAll: false,
        connectors:   {
            'alice':                {
                skip:              false,
                overwrite:         false,
                input:             path.join(ca_testbed, 'ec/ids/component/alice/connector/client'),
                transport:         path.join(ca_testbed, 'ec/ids/component/alice/tls-server/server'),
                output:            path.join(daps_data, 'connector/alice/connector'),
                endpointURL:       'https://alice.nicos-rd.com/',
                extendedGuarantee: [
                    'idsc:AUDIT_NONE',
                    'idsc:INTEGRITY_PROTECTION_NONE',
                    'idsc:USAGE_CONTROL_NONE'
                ]
            },
            'bob':                  {
                skip:              false,
                overwrite:         false,
                input:             path.join(ca_testbed, 'ec/ids/component/bob/connector/client'),
                transport:         path.join(ca_testbed, 'ec/ids/component/bob/tls-server/server'),
                output:            path.join(daps_data, 'connector/bob/connector'),
                endpointURL:       'https://bob.nicos-rd.com/',
                extendedGuarantee: [
                    'idsc:AUDIT_NONE',
                    'idsc:INTEGRITY_PROTECTION_NONE',
                    'idsc:USAGE_CONTROL_NONE'
                ]
            },
            'FIRWARE/dev':          {
                input:       path.join(ca_testbed, 'ec/ids/cut/FIWARE/dev/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/FIWARE/dev/tls-server/server'),
                output:      path.join(daps_data, 'connector/FIWARE/dev/connector'),
                endpointURL: 'https://fiware.dev/'
            },
            'FIRWARE/car-kim':      {
                input:       path.join(ca_testbed, 'ec/ids/cut/FIWARE/car-kim/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/FIWARE/car-kim/tls-server/server'),
                output:      path.join(daps_data, 'connector/FIWARE/car-kim/connector'),
                endpointURL: 'https://car-kim.fiware-dataspace-connector.org/'
            },
            'FIRWARE/platform-kim': {
                input:       path.join(ca_testbed, 'ec/ids/cut/FIWARE/platform-kim/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/FIWARE/platform-kim/tls-server/server'),
                output:      path.join(daps_data, 'connector/FIWARE/platform-kim/connector'),
                endpointURL: 'https://platform-kim.fiware-dataspace-connector.org/'
            },
            'WNW/FIT-1':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/WNW/FIT/1/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/WNW/FIT/1/tls-server/server'),
                output:      path.join(daps_data, 'connector/WNW/FIT-1/connector'),
                endpointURL: 'https://www.fit.fraunhofer.de/'
            },
            'WNW/FIT-2':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/WNW/FIT/2/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/WNW/FIT/2/tls-server/server'),
                output:      path.join(daps_data, 'connector/WNW/FIT-2/connector'),
                endpointURL: 'https://www.fit.fraunhofer.de/'
            },
            'WNW/FIT-3':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/WNW/FIT/3/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/WNW/FIT/3/tls-server/server'),
                output:      path.join(daps_data, 'connector/WNW/FIT-3/connector'),
                endpointURL: 'https://www.fit.fraunhofer.de/'
            },
            'WNW/IMW-1':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/WNW/IMW/1/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/WNW/IMW/1/tls-server/server'),
                output:      path.join(daps_data, 'connector/WNW/IMW-1/connector'),
                endpointURL: 'https://www.imw.fraunhofer.de/'
            },
            'WNW/IMW-2':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/WNW/IMW/2/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/WNW/IMW/2/tls-server/server'),
                output:      path.join(daps_data, 'connector/WNW/IMW-2/connector'),
                endpointURL: 'https://www.imw.fraunhofer.de/'
            },
            'WNW/IMW-3':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/WNW/IMW/3/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/WNW/IMW/3/tls-server/server'),
                output:      path.join(daps_data, 'connector/WNW/IMW-3/connector'),
                endpointURL: 'https://www.imw.fraunhofer.de/'
            },
            'DBX/SWC-1':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/DBX/SWC/1/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/DBX/SWC/1/tls-server/server'),
                output:      path.join(daps_data, 'connector/DBX/SWC-1/connector'),
                endpointURL: 'https://semantic-web.com/'
            },
            'DBX/SWC-2':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/DBX/SWC/2/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/DBX/SWC/2/tls-server/server'),
                output:      path.join(daps_data, 'connector/DBX/SWC-2/connector'),
                endpointURL: 'https://semantic-web.com/'
            },
            'DBX/SWC-3':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/DBX/SWC/3/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/DBX/SWC/3/tls-server/server'),
                output:      path.join(daps_data, 'connector/DBX/SWC-3/connector'),
                endpointURL: 'https://semantic-web.com/'
            },
            'DBX/DUM-1':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/DBX/DUM/1/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/DBX/DUM/1/tls-server/server'),
                output:      path.join(daps_data, 'connector/DBX/DUM-1/connector'),
                endpointURL: 'http://example.org/'
            },
            'DBX/DUM-2':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/DBX/DUM/2/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/DBX/DUM/2/tls-server/server'),
                output:      path.join(daps_data, 'connector/DBX/DUM-2/connector'),
                endpointURL: 'http://example.org/'
            },
            'DBX/DUM-3':            {
                input:       path.join(ca_testbed, 'ec/ids/cut/DBX/DUM/3/connector/client'),
                transport:   path.join(ca_testbed, 'ec/ids/cut/DBX/DUM/3/tls-server/server'),
                output:      path.join(daps_data, 'connector/DBX/DUM-3/connector'),
                endpointURL: 'http://example.org/'
            }
        }
    };

console.time('done');
Promise.all(Object.entries(config.connectors).map(async function importConnectors([connectorName, connectorConfig]) {

    try {
        if (config.skipAll || connectorConfig.skip) return;
        const
            outputDir = path.dirname(connectorConfig.output),
            dirStats  = await fs.stat(outputDir);
        if (!dirStats.isDirectory()) throw new Error(`expected ${outputDir} to be a directory`);
        if (!(config.overwriteAll || connectorConfig.overwrite)) return;
    } catch (err) {
        if (err.code !== 'ENOENT') throw err;
    }

    const
        outputName   = path.basename(connectorConfig.output),
        connectorURI = path.relative(daps_data, path.dirname(connectorConfig.output)).replace(/\\/g, '/').replace(/\/(?=[^/]+$)/, '#');

    const [inputMeta, transportMeta, publicKey] = await Promise.all([
        fs.readFile(connectorConfig.input + '.json', 'utf-8').then(data => JSON.parse(data)),
        fs.readFile(connectorConfig.transport + '.json', 'utf-8').then(data => JSON.parse(data)),
        fs.readFile(connectorConfig.input + '.pub'),
        fs.mkdir(path.dirname(connectorConfig.output), {recursive: true})
    ]);

    await Promise.all([
        fs.copyFile(connectorConfig.input + '.pub', connectorConfig.output + '.pub'),
        fs.copyFile(connectorConfig.input + '.cert', connectorConfig.output + '.cert'),
        fs.copyFile(connectorConfig.input + '.json', connectorConfig.output + '.json')
    ]);

    await Promise.all([
        fs.writeFile(connectorConfig.output + '.js', [
            `const fs          = require('fs'), path = require('path'), crypto = require('crypto');`,
            `const load        = (filename) => fs.readFileSync(path.join(__dirname, filename));`,
            `exports.meta      = require('./${outputName}.json');`,
            `exports.pub       = load('./${outputName}.pub');`,
            `exports.publicKey = crypto.createPublicKey(exports.pub);`,
            `exports.cert      = load('./${outputName}.cert');`,
            `Object.freeze(exports);`
        ].join('\n')),
        fs.writeFile(connectorConfig.output + '.ttl', [
            `@prefix dct:  <http://purl.org/dc/terms/> .`,
            `@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .`,
            `@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .`,
            ``,
            `@prefix ids:  <https://w3id.org/idsa/core/> .`,
            `@prefix idsc: <https://w3id.org/idsa/code/> .`,
            ``,
            `@prefix fua:  <https://www.nicos-rd.com/fua#> .`,
            `@prefix daps: <https://www.nicos-rd.com/fua/daps#> .`,
            ``,
            `@base <${config.baseURL}> .`,
            ``,
            `<${connectorURI}>`,
            `    a                        ids:Connector, ids:BaseConnector ;`,
            `    ids:securityProfile      idsc:BASE_SECURITY_PROFILE ;`,
            connectorConfig.extendedGuarantee?.length
                ? connectorConfig.extendedGuarantee.map(value => `    ids:extendedGuarantee    ${value} ;`).join('\n')
                : `    # ids:extendedGuarantee    <...> ;`,
            `    ids:transportCertsSha256 "${transportMeta.certSha256Fingerprint}" ;`,
            `    ids:publicKey            [ a            ids:PublicKey ;`,
            `                               daps:keyId   "${inputMeta.SKIAKI}" ;`,
            `                               ids:keyType  idsc:RSA ;`,
            `                               ids:keyValue """`,
            // publicKey.toString('utf-8')
            //     .split(/[\r\n]+/g)
            //     .map(line => line.trim())
            //     .filter(line => line)
            //     .map(line => '                                   ' + line)
            //     .join('\n'),
            publicKey.toString('base64')
                .match(/.{1,64}/g)
                .map(line => '                                   ' + line)
                .join('\n'),
            `                               """^^xsd:base64Binary ; ] ;`,
            `    ids:hasEndpoint          [ a             ids:ConnectorEndpoint ;`,
            `                               ids:accessURL "${connectorConfig.endpointURL}"^^xsd:anyURI ; ] ;`,
            `    ids:authInfo             [ a                ids:AuthInfo ;`,
            `                               ids:authService  <> ;`,
            `                               ids:authStandard idsc:OAUTH2_JWT ; ] ;`,
            `.`
        ].join('\n'))
    ]);

    console.log('imported: ' + connectorName);

})).then(() => console.timeEnd('done')).catch(console.error);
