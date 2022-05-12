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
                const payload = agent.createJWKS();
                response.type('json').send(JSON.stringify(payload));
            } catch (err) {
                next(err);
            }
        }
    );

    agent.app.post(
        '/token',
        express.urlencoded({extended: false}),
        async function (request, response, next) {
            try {
                const payload = await agent.createDatResponse({requestParam: request.body});
                response.type('json').send(JSON.stringify(payload));
            } catch (err) {
                next(err);
            }
        }
    );

    await agent.listen();
    util.logText(`daps app is listening at <${agent.url}>`);
    agent.once('closed', () => util.logText('daps app has closed'));

}; // module.exports = DAPSApp
