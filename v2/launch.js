#!/usr/bin/env node

const
    path = require('path'),
    App  = require('@nrd/fua.agent.app'),
    DAPS = require('./code/daps.js'),
    tty  = require('@nrd/fua.core.tty');

App.launch({
    app:    require('./app.js'),
    config: require('./config.json'),
    async initialize(config) {
        tty.log('initialize daps');
        await DAPS.initialize(config.daps || {});

        return {daps: DAPS};
    },
    space:  {
        store: {
            module:  'filesystem',
            options: {
                defaultFile: 'file://data.ttl',
                loadFiles:   [
                    {
                        'dct:identifier': path.join(__dirname, '../data/load.json'),
                        'dct:format':     'application/fua.load+json'
                    },
                    require('@nrd/fua.resource.ontology.core')
                ]
            }
        }
    },
    domain: true,
    helmut: true,
    amec:   true,
    server: true
});
