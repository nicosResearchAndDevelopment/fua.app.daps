const
    config    = require('./config/config.daps.js'),
    util      = require('./code/util.daps.js'),
    DAPSAgent = require('./code/agent.daps.js'),
    DAPSApp   = require('./app.daps.js'),
    DAPSLab   = require('./lab.daps.js');

(async function LaunchDAPS() {

    const dapsAgent = await DAPSAgent.create({
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

    await DAPSLab({
        'config': config,
        'agent':  dapsAgent
    });

})().catch((err) => {
    util.logError(err);
    debugger;
    process.exit(1);
}); // LaunchDAPS
