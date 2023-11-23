const
    {describe, test, before, after} = require('mocha'),
    expect                          = require('expect'),
    path                            = require('path'),
    {SignJWT, jwtVerify}            = require('jose'),
    socketIoClient                  = require('socket.io-client'),
    is                              = require('@nrd/fua.core.is'),
    errors                          = require('@nrd/fua.core.errors'),
    ts                              = require('@nrd/fua.core.ts'),
    subprocess                      = require('@nrd/fua.module.subprocess'),
    DAPSClient                      = require('@nrd/fua.ids.client.daps'),
    alice                           = require('./alice/index.js'),
    config                          = {
        verbose:       false,
        windup_time:   ts.duration('20s'),
        check_delay:   ts.duration('200ms'),
        url:           'http://localhost:3000/',
        issuer:        'https://daps.tb.nicos-rd.com/',
        authorization: 'Basic ' + Buffer.from('testbed:testing').toString('base64')
    };

describe('fua.app.daps.tweak', function () {

    this.timeout('60s');

    let childProcess, dapsClient;

    before('init', async function () {
        childProcess = subprocess.RunningProcess('node', {
            cwd:     path.join(__dirname, '..'),
            verbose: config.verbose
        })('src/launch.js');
        const maxTS  = ts() + config.windup_time;
        while (true) {
            try {
                const response = await fetch(config.url);
                expect(response.ok).toBeTruthy();
                const result = await response.json();
                expect(result).toMatchObject({issuer: config.issuer})
                if (config.verbose) console.log('Response:', result);
                break;
            } catch (err) {
                if (ts() > maxTS) throw err;
                await ts.pause(config.check_delay);
            }
        }
        dapsClient = new DAPSClient({
            SKIAKI:        alice.client.meta.SKIAKI,
            privateKey:    alice.client.privateKey,
            dapsUrl:       config.url,
            dapsTokenPath: '/token',
            dapsJwksPath:  '/jwks.json'
        });
    });

    after('exit', async function () {
        childProcess?.kill();
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
                sub: alice.client.meta.SKIAKI
            });
        });

        test('get the meta information', async function () {
            const request = await fetch(`${config.url}about`);
            expect(request.ok).toBeTruthy();
            const metaInfo = await request.json();
            expect(metaInfo).toMatchObject({
                // issuer: config.url
                issuer: config.issuer
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
                    iss:        alice.client.meta.SKIAKI,
                    sub:        alice.client.meta.SKIAKI,
                    aud:        config.url,
                    exp:        currentTime + 60,
                    nbf:        currentTime - 10,
                    iat:        currentTime,
                    ...customPayload
                },
                datRequestToken   = await new SignJWT(datRequestPayload)
                    .setProtectedHeader(datRequestHeader)
                    .sign(alice.client.privateKey);
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
                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {
                        'Authorization': config.authorization,
                        'Content-Type':  'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        },
                        count: 1
                    })
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
                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {
                        'Authorization': config.authorization,
                        'Content-Type':  'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        },
                        end:   Date.now() + 1e3
                    })
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
                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {
                        'Authorization': config.authorization,
                        'Content-Type':  'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        }
                    })
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {
                        'Authorization': config.authorization,
                        'Content-Type':  'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'delete',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        }
                    })
                });

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).not.toMatchObject({
                    custom: 'test'
                });
            });

            test('and update it after first request, then remove for cleanup', async function () {
                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {
                        'Authorization': config.authorization,
                        'Content-Type':  'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'create',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'test'
                        }
                    })
                });

                const datRequest = await dapsClient.createDatRequest();
                const response   = await fetch(datRequest.url, datRequest);
                expect(response.ok).toBeTruthy();
                const {access_token: accessToken} = await response.json();
                const datPayload                  = dapsClient.decodeToken(accessToken);
                expect(datPayload).toMatchObject({
                    custom: 'test'
                });

                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {
                        'Authorization': config.authorization,
                        'Content-Type':  'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'update',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        },
                        tweak: {
                            custom: 'lorem'
                        }
                    })
                });

                const secondResponse = await fetch(datRequest.url, datRequest);
                expect(secondResponse.ok).toBeTruthy();
                const {access_token: secondAccessToken} = await secondResponse.json();
                const secondDatPayload                  = dapsClient.decodeToken(secondAccessToken);
                expect(secondDatPayload).toMatchObject({
                    custom: 'lorem'
                });

                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {'Content-Type': 'application/json'},
                    body:    JSON.stringify({
                        type:  'delete',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        }
                    })
                });

                await fetch(`${config.url}tweak`, {
                    method:  'POST',
                    headers: {
                        'Authorization': config.authorization,
                        'Content-Type':  'application/json'
                    },
                    body:    JSON.stringify({
                        type:  'delete',
                        match: {
                            sub: alice.client.meta.SKIAKI
                        }
                    })
                });

                const thirdResponse = await fetch(datRequest.url, datRequest);
                expect(thirdResponse.ok).toBeTruthy();
            });

        });

        describe('add a custom property via the tweak matcher over socket.io', function () {

            let ioSocket = null;

            before('connect io', async function () {
                ioSocket = socketIoClient.io(`${config.url}tweak`, {
                    extraHeaders: {
                        'Authorization': config.authorization
                    }
                });
                if (!ioSocket.connected) await new Promise((resolve, reject) => {
                    ioSocket.once('connect', resolve);
                    ioSocket.once('connect_error', reject);
                });
            });

            after('close io', function () {
                ioSocket.close();
                ioSocket = null;
            });

            function callIO(eventName, ...args) {
                return new Promise((resolve, reject) => {
                    const acknowledge = (err, result) => {
                        if (!err) resolve(result);
                        else if (err instanceof Error) reject(err);
                        else if (is.object(err)) reject(errors.fromJSON(err))
                        else reject(new Error(err));
                    };
                    ioSocket.emit(eventName, ...args, acknowledge);
                });
            }

            test('for 1 request', async function () {
                await callIO('create', {
                    match: {
                        sub: alice.client.meta.SKIAKI
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
                        sub: alice.client.meta.SKIAKI
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
                        sub: alice.client.meta.SKIAKI
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
                        sub: alice.client.meta.SKIAKI
                    }
                });
            });

        });

    });

});
