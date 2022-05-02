const
    config    = require('./config/config.daps.js'),
    util      = require('./code/util.daps.js'),
    DAPSAgent = require('./code/agent.daps.js'),
    DAPSApp   = require('./app.daps.js'),
    DAPSLab   = require('./lab.daps.js');

(async function LaunchDAPS() {

    const dapsAgent = await DAPSAgent.create({

        // TODO

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
