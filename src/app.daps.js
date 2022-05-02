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

    const
        app = agent.app,
        io  = agent.io;

    // TODO

    await agent.listen();
    util.logText(`daps app is listening at <${agent.url}>`);

}; // module.exports = DAPSApp
