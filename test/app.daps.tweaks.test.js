const
    {describe, test}     = require('mocha'),
    expect               = require('expect'),
    https                = require('https'),
    fetch                = require('node-fetch'),
    socketIoClient       = require('socket.io-client'),
    {SignJWT, jwtVerify} = require('jose'),
    config               = require('../src/config/config.daps.js'),
    tls_config           = require('./alice-cert/tls-server/server.js'),
    cert_config          = require('./alice-cert/connector/client.js'),
    DAPSAgent            = require('../src/code/agent.daps.js'),
    DAPSClient           = require('@nrd/fua.ids.client.daps'),
    DAPSApp              = require('../src/app.daps.js'),
    baseUrl              = `${config.server.schema}://${config.server.hostname}:${config.server.port}/`,
    httpAgent            = new https.Agent({
        key:                tls_config.key,
        cert:               tls_config.cert,
        ca:                 tls_config.ca,
        rejectUnauthorized: false
    });

describe('app.daps.tweaks', function () {

    this.timeout('60s');

    let dapsAgent, dapsClient;

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
                tokenPath: '/token',
                jwksPath:  '/jwks.json',
                aboutPath: '/about',
                tweakDat:  {
                    configPath: '/tweak',
                    pipeTweaks: [
                        'custom'
                    ]
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
    });

    after('close the agent', async function () {
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

    describe('tweaked usage', function () {

        async function _createDatRequestToken(customPayload) {
            const
                currentTime       = Math.floor(1e-3 * Date.now()),
                datRequestHeader  = {
                    alg: 'RS256'
                },
                datRequestPayload = {
                    '@context': 'https://w3id.org/idsa/contexts/context.jsonld',
                    '@type':    'DatRequestPayload', // 'ids:DatRequestToken'
                    iss:        cert_config.meta.SKIAKI,
                    sub:        cert_config.meta.SKIAKI,
                    aud:        baseUrl,
                    exp:        currentTime + 60,
                    nbf:        currentTime - 10,
                    iat:        currentTime,
                    ...customPayload
                },
                datRequestToken   = await new SignJWT(datRequestPayload)
                    .setProtectedHeader(datRequestHeader)
                    .sign(cert_config.privateKey);
            return datRequestToken;
        } // _createDatRequestToken

        test('add a custom property via the request payload', async function () {
            const datRequest = await dapsClient.createDatRequest({
                datRequestToken: await _createDatRequestToken({
                    tweakDat: {
                        custom: 'test'
                    }
                })
            });
            const response   = await fetch(datRequest.url, datRequest);
            expect(response.ok).toBeTruthy();
            const {access_token} = await response.json();
            const datPayload     = dapsClient.decodeToken(access_token);
            expect(datPayload).toMatchObject({
                custom: 'test'
            });
        });

        describe('add a custom property via the tweak matcher', function () {

            test('for 1 request', async function () {
                await fetch(`${baseUrl}tweak`, {
                    method:  'POST',
                    headers: {
                        // 'Authorization': 'Basic ...',
                        // 'Authorization': 'Bearer ...',
                        'Content-Type': 'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: cert_config.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        },
                        count: 1
                    }),
                    agent:   httpAgent
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).not.toMatchObject({
                    custom: 'test'
                });
            });

            test('for 1 second', async function () {
                await fetch(`${baseUrl}tweak`, {
                    method:  'POST',
                    headers: {'Content-Type': 'application/json'},
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: cert_config.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        },
                        end:   Date.now() / 1e3 + 1
                    }),
                    agent:   httpAgent
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                await new Promise(resolve => setTimeout(resolve, 1e3));

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).not.toMatchObject({
                    custom: 'test'
                });
            });

            test('and remove it after first request', async function () {
                await fetch(`${baseUrl}tweak`, {
                    method:  'POST',
                    headers: {'Content-Type': 'application/json'},
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: cert_config.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        }
                    }),
                    agent:   httpAgent
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                await fetch(`${baseUrl}tweak`, {
                    method:  'POST',
                    headers: {'Content-Type': 'application/json'},
                    body:    JSON.stringify({
                        type:  'delete',
                        match: {
                            sub: cert_config.meta.SKIAKI
                        }
                    }),
                    agent:   httpAgent
                });

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).not.toMatchObject({
                    custom: 'test'
                });
            });

            test('and update it after first request', async function () {
                await fetch(`${baseUrl}tweak`, {
                    method:  'POST',
                    headers: {'Content-Type': 'application/json'},
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: cert_config.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        }
                    }),
                    agent:   httpAgent
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                await fetch(`${baseUrl}tweak`, {
                    method:  'POST',
                    headers: {'Content-Type': 'application/json'},
                    body:    JSON.stringify({
                        type:  'update',
                        match: {
                            sub: cert_config.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'lorem'
                        }
                    }),
                    agent:   httpAgent
                });

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).toMatchObject({
                    custom: 'lorem'
                });

                await fetch(`${baseUrl}tweak`, {
                    method:  'POST',
                    headers: {'Content-Type': 'application/json'},
                    body:    JSON.stringify({
                        type:  'delete',
                        match: {
                            sub: cert_config.meta.SKIAKI
                        }
                    }),
                    agent:   httpAgent
                });
            });

        });

        describe('add a custom property via the tweak matcher over socket.io', function () {

            let ioSocket = null;

            before('connect io', async function () {
                ioSocket = socketIoClient.io(`${baseUrl}tweak`, {agent: httpAgent});
                if (!ioSocket.connected) await new Promise(resolve => ioSocket.once('connect', resolve));
            });

            after('close io', function () {
                ioSocket.close();
                ioSocket = null;
            });

            function callIO(eventName, ...args) {
                return new Promise((resolve, reject) => {
                    const acknowledge = (err, result) => err ? reject(err) : resolve(result);
                    ioSocket.emit(eventName, ...args, acknowledge);
                });
            }

            test('for 1 request', async function () {
                await callIO('create', {
                    match: {
                        sub: cert_config.meta.SKIAKI
                    },
                    tweak: {
                        custom: 'test'
                    },
                    count: 1
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).not.toMatchObject({
                    custom: 'test'
                });
            });

            test('and update it after first request', async function () {
                await callIO('create', {
                    match: {
                        sub: cert_config.meta.SKIAKI
                    },
                    tweak: {
                        custom: 'test'
                    }
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                await callIO('update', {
                    match: {
                        sub: cert_config.meta.SKIAKI
                    },
                    tweak: {
                        custom: 'lorem'
                    }
                });

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).toMatchObject({
                    custom: 'lorem'
                });

                await callIO('delete', {
                    match: {
                        sub: cert_config.meta.SKIAKI
                    }
                });
            });

        });

    });

});
