const
    util    = require('./code/util.daps.js'),
    path    = require('path'),
    express = require('express');

module.exports = async function DAPSApp(
    {
        'config': config,
        'agent':  agent
    }
) {

    agent.app.get(
        '/.well-known/jwks.json',
        async function (request, response, next) {
            try {
                const jwks    = await agent.generateJWKS();
                const payload = JSON.stringify(jwks);
                response.type('json').send(payload);
            } catch (err) {
                next(err);
            }
        }
    );

    agent.app.post(
        '/token',
        express.text(),
        async function (request, response, next) {
            try {
                const
                    datRequestParam = agent.parseDatRequestQuery(request.body),
                    datRequest      = await agent.parseDatRequestToken(datRequestParam.client_assertion),
                    datHeader       = agent.createDatHeader(datRequest),
                    datPayload      = await agent.createDatPayload(datRequest),
                    dat             = await agent.createDat(datPayload, datHeader),
                    payload         = JSON.stringify({
                        alg:          datHeader.alg,
                        typ:          'JWT',
                        kid:          datHeader.kid,
                        access_token: dat,
                        signature:    null
                    });
                response.type('json').send(payload);
            } catch (err) {
                next(err);
            }
        }
    );

    await agent.listen();
    util.logText(`daps app is listening at <${agent.url}>`);

}; // module.exports = DAPSApp
