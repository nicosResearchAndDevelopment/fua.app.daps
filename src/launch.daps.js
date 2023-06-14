#!/usr/bin/env node

// const
//     BasicAuth = require('@nrd/fua.agent.amec/BasicAuth'),
//     DatAuth   = require('@nrd/fua.agent.amec/DatAuth');

require('@nrd/fua.core.app').launch({
    config: {
        default: require('./config/config.daps.js')
    },
    agent:  {
        class:  require('./code/agent.daps.js'),
        param:  {
            app:    true,
            io:     true,
            domain: true
        },
        mapper: (config) => ({
            uri:      config.space.uri,
            schema:   config.server.schema,
            hostname: config.server.hostname,
            port:     config.server.port,
            context:  config.space.context,
            store:    config.space.store,
            server:   config.server.options,
            daps:     config.daps
        }),
        async setup({agent, config}) {
            // TODO configure amec correctly
            // dapsAgent.amec.registerMechanism(BasicAuth.prefLabel, BasicAuth({domain: dapsAgent.domain}));
            // dapsAgent.amec.registerMechanism(DatAuth.prefLabel, DatAuth({connector: dapsAgent.connector}));
        }
    },
    app:    {
        launch:  require('./app.daps.js'),
        develop: require('./lab.daps.js')
    }
});
