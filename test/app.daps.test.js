const
    {describe, test} = require('mocha'),
    expect           = require('expect'),
    https            = require('https'),
    fetch            = require('node-fetch'),
    config           = require('../src/config/config.daps.js'),
    tls_config       = require('./alice-cert/tls-server/server.js'),
    cert_config      = require('./alice-cert/connector/client.js'),
    DAPSAgent        = require('../src/code/agent.daps.js'),
    DAPSClient       = require('@nrd/fua.ids.client.daps'),
    DAPSApp          = require('../src/app.daps.js'),
    baseUrl          = `${config.server.schema}://${config.server.hostname}:${config.server.port}/`,
    httpAgent        = new https.Agent({
        key:  tls_config.key,
        cert: tls_config.cert,
        ca:   tls_config.ca
    });

describe('app.daps', function () {

    this.timeout('60s');

    let dapsAgent = null;

    before('initialize agent and start app', async function () {
        dapsAgent = await DAPSAgent.create({
            schema:   config.server.schema,
            hostname: config.server.hostname,
            port:     config.server.port,
            context:  config.space.context,
            store:    config.space.store,
            server:   config.server.options,
            app:      true,
            domain:   true
        });
        await DAPSApp({
            'config': config,
            'agent':  dapsAgent
        });
    });

    after('close the agent', async function () {
        await dapsAgent.close();
    });

    test('get the jwks.json with the usual route', async function () {
        const response = await fetch(baseUrl + '.well-known/jwks.json', {
            agent: httpAgent
        });
        expect(response.ok).toBeTruthy();
        const jwks = await response.json();
        expect(Array.isArray(jwks?.keys)).toBeTruthy();
        for (let key of jwks.keys) {
            expect(typeof key?.kid).toBe('string');
            expect(typeof key?.kty).toBe('string');
        }
    });

    describe('use the daps.client', function () {

        let dapsClient = null;

        before('construct the daps client', function () {
            dapsClient = new DAPSClient({
                SKIAKI:       cert_config.meta.SKIAKI,
                dapsUrl:      baseUrl,
                privateKey:   cert_config.privateKey,
                requestAgent: httpAgent
            });
        });

        test('get the jwks', async function () {
            const jwks = await dapsClient.getJwks();
            expect(Array.isArray(jwks?.keys)).toBeTruthy();
            for (let key of jwks.keys) {
                expect(typeof key?.kid).toBe('string');
                expect(typeof key?.kty).toBe('string');
            }
        });

        test('get a dat and validate it', async function () {
            const dat = await dapsClient.getDat();
            expect(typeof dat).toBe('string');
            const datPayload = await dapsClient.validateDat(dat);
            expect(datPayload).toMatchObject({
                sub: cert_config.meta.SKIAKI
            });
        });

    });

});
