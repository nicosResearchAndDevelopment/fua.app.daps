const
    config    = require('./config/config.daps.js'),
    util      = require('./code/util.daps.js'),
    // BasicAuth = require('@nrd/fua.agent.amec/BasicAuth'),
    // DatAuth   = require('@nrd/fua.agent.amec/DatAuth'),
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
        // amec:     true
    });

    /* 2. Use additional methods to configure the setup: */

    // TODO configure amec correctly
    // dapsAgent.amec.registerMechanism(BasicAuth.prefLabel, BasicAuth({domain: dapsAgent.domain}));
    // dapsAgent.amec.registerMechanism(DatAuth.prefLabel, DatAuth({connector: dapsAgent.connector}));

    /* 3. Launch the main app: */

    await DAPSApp({
        'config': config,
        'agent':  dapsAgent
    });

    /* 4. Launch the testing lab: */

    if (!util.NODE_PROD) await DAPSLab({
        'config': config,
        'agent':  dapsAgent
    });

})().catch((err) => {

    /* ERR. Log any error during launch and exit the application: */

    util.logError(err);
    debugger;
    process.exit(1);

}); // LaunchDAPS
