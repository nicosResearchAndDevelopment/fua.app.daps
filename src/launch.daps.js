const
    config    = require('./config/config.daps.js'),
    util      = require('./code/util.daps.js'),
    DAPSAgent = require('./code/agent.daps.js'),
    DAPSApp   = require('./app.daps.js'),
    DAPSLab   = require('./lab.daps.js');

(async function LaunchDAPS() {

    /* 1. Construct a server agent for your setup: */

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

    /* 2. Use additional methods to configure the setup: */

    /* 3. Launch the main app: */

    await DAPSApp({
        'config': config,
        'agent':  dapsAgent
    });

    /* 4. Launch the testing lab: */

    await DAPSLab({
        'config': config,
        'agent':  dapsAgent
    });

})().catch((err) => {

    /* ERR. Log any error during launch and exit the application: */

    util.logError(err);
    debugger;
    process.exit(1);

}); // LaunchDAPS
