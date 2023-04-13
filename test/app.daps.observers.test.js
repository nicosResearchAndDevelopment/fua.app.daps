const
    {describe, test} = require('mocha'),
    expect           = require('expect'),
    https            = require('https'),
    fetch            = require('node-fetch'),
    socketIoClient   = require('socket.io-client'),
    util             = require('@nrd/fua.core.util'),
    config           = require('../src/config/config.daps.js'),
    tls_config       = require('./alice-cert/tls-server/server.js'),
    cert_config      = require('./alice-cert/connector/client.js'),
    DAPSAgent        = require('../src/code/agent.daps.js'),
    DAPSClient       = require('@nrd/fua.ids.client.daps'),
    DAPSApp          = require('../src/app.daps.js'),
    baseUrl          = `${config.server.schema}://${config.server.hostname}:${config.server.port}/`,
    httpAgent        = new https.Agent({
        key:                tls_config.key,
        cert:               tls_config.cert,
        ca:                 tls_config.ca,
        rejectUnauthorized: false
    });

describe('app.daps.observers', function () {

    this.timeout('60s');

    let dapsAgent, dapsClient, ioSocket;

    before('initialize agent, app and client', async function () {
        dapsAgent = await DAPSAgent.create({
            schema:   config.server.schema,
            hostname: config.server.hostname,
            port:     config.server.port,
            context:  config.space.context,
            store:    config.space.store,
            server:   config.server.options,
            app:      true,
            io:       true,
            domain:   true
        });
        await DAPSApp({
            'config': {
                tokenPath:       '/token',
                jwksPath:        '/jwks.json',
                aboutPath:       '/about',
                requestObserver: {
                    namespacePath: '/observe'
                }
            },
            'agent':  dapsAgent
        });
        dapsClient = new DAPSClient({
            SKIAKI:        cert_config.meta.SKIAKI,
            dapsUrl:       baseUrl,
            privateKey:    cert_config.privateKey,
            requestAgent:  httpAgent,
            dapsTokenPath: '/token',
            dapsJwksPath:  '/jwks.json'
        });
        ioSocket   = socketIoClient.io(`${baseUrl}observe`, {agent: httpAgent});
        if (!ioSocket.connected) await new Promise(resolve => ioSocket.once('connect', resolve));
        ioSocket.on('request', data => console.dir(data, {depth: 1}));
        ioSocket.on('token', util.logObject);
    });

    after('close the agent', async function () {
        ioSocket.close();
        await dapsAgent.close();
    });

    describe('basic usage', function () {

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

        test('get the meta information', async function () {
            const request = await fetch(`${baseUrl}about`, {agent: httpAgent});
            expect(request.ok).toBeTruthy();
            const metaInfo = await request.json();
            expect(metaInfo).toMatchObject({
                // issuer: baseUrl
                issuer: `${config.server.schema}://${config.server.hostname}/`
            });
        });

    });

});
