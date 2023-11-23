const
    {describe, test, before, beforeEach} = require('mocha'),
    expect                               = require('expect'),
    https                                = require('https'),
    fetch                                = require('node-fetch'),
    DAPSClient                           = require('@nrd/fua.ids.client.daps'),
    baseUrl                              = 'https://daps.tb.nicos-rd.com/',
    alice                                = require('./alice/index.js'),
    httpAgent                            = new https.Agent({
        key:                alice.server.key,
        cert:               alice.server.cert,
        ca:                 alice.server.ca,
        rejectUnauthorized: false
    });

describe('fua.app.daps.server', function () {

    this.timeout('60s');

    test('get the jwks.json with the usual route', async function () {
        const response = await fetch(baseUrl + '.well-known/jwks.json', {
            agent: httpAgent
        });
        expect(response.ok).toBeTruthy();
        const jwks = await response.json();
        console.log(jwks);
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
                SKIAKI:       alice.client.meta.SKIAKI,
                dapsUrl:      baseUrl,
                privateKey:   alice.client.privateKey,
                requestAgent: httpAgent
            });
        });

        test('get the jwks', async function () {
            const jwks = await dapsClient.getJwks();
            console.log(jwks);
            expect(Array.isArray(jwks?.keys)).toBeTruthy();
            for (let key of jwks.keys) {
                expect(typeof key?.kid).toBe('string');
                expect(typeof key?.kty).toBe('string');
            }
        });

        test('get a dat and validate it', async function () {
            const dat = await dapsClient.getDat();
            console.log(dat);
            expect(typeof dat).toBe('string');
            const datPayload = await dapsClient.validateDat(dat);
            console.log(datPayload);
            expect(datPayload).toMatchObject({
                sub: alice.client.meta.SKIAKI
            });
        });

    });

    describe('test the DAT Request for all certificates', function () {

        const certificates = [
            // alice+bob
            require('../../../script/ca/resources/nrd-testbed/ec/ids/component/alice/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/component/bob/connector/client.js'),
            // FIWARE
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/FIWARE/dev/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/FIWARE/platform-kim/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/FIWARE/car-kim/connector/client.js'),
            // WertNetzWerke
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/WNW/FIT/1/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/WNW/FIT/2/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/WNW/FIT/3/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/WNW/IMW/1/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/WNW/IMW/2/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/WNW/IMW/3/connector/client.js'),
            // DataBri-X
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/DBX/SWC/1/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/DBX/SWC/2/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/DBX/SWC/3/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/DBX/DUM/1/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/DBX/DUM/2/connector/client.js'),
            require('../../../script/ca/resources/nrd-testbed/ec/ids/cut/DBX/DUM/3/connector/client.js')
        ];

        certificates.forEach((cert) => test(cert.meta.SKIAKI, async function () {

            expect(cert).toHaveProperty('privateKey');
            const dapsClient = new DAPSClient({
                SKIAKI:       cert.meta.SKIAKI,
                dapsUrl:      baseUrl,
                privateKey:   cert.privateKey,
                requestAgent: httpAgent
            });

            const dat = await dapsClient.getDat();
            console.log(dat);
            expect(typeof dat).toBe('string');

            const datPayload = await dapsClient.validateDat(dat);
            console.log(datPayload);
            expect(datPayload).toMatchObject({
                sub: cert.meta.SKIAKI
            });

        }));

    });

});
