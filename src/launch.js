#!/usr/bin/env node

const
    path = require('path'),
    App  = require('@nrd/fua.agent.app'),
    DAPS = require('./app/daps.js'),
    tty  = require('@nrd/fua.core.tty');

App.launch({
    app: require('./app/app.js'),
    async initialize(config) {
        tty.log('initialize daps');
        await DAPS.initialize(config.daps || {});

        return {daps: DAPS};
    },
    config: {
        app:  {
            tokenPath:       ['/token', '/auth/token'],
            jwksPath:        ['/jwks.json', '/.well-known/jwks.json', '/auth/jwks.json', '/auth/.well-known/jwks.json'],
            aboutPath:       ['/', '/about', '/.well-known/openid-configuration', '/auth/.well-known/openid-configuration'],
            tweakDat:        {
                pipeTweaks: ['custom'],
                configPath: '/tweak'
            },
            requestObserver: {
                namespacePath: '/observe'
            }
        },
        daps: {
            uri:  'https://daps.tb.nicos-rd.com/',
            meta: {
                tokenPath: '/token',
                jwksPath:  '/.well-known/jwks.json',
                aboutPath: '/.well-known/openid-configuration'
            }
        }
    },
    server: {
        port:    3000,
        app:     true,
        io:      true,
        session: {
            secret:            '@nrd/fua.app.daps',
            resave:            false,
            saveUninitialized: false
        }
    },
    space:  {
        context: {
            'ids':  'https://w3id.org/idsa/core/',
            'idsc': 'https://w3id.org/idsa/code/',
            'fua':  'https://www.nicos-rd.com/fua#',
            'dom':  'https://www.nicos-rd.com/fua/domain#',
            'ecm':  'https://www.nicos-rd.com/fua/ecosystem#',
            'daps': 'https://www.nicos-rd.com/fua/daps#'
        },
        store:   {
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
    domain: {
        uri: 'https://daps.tb.nicos-rd.com/domain/'
    },
    amec:   {
        mechanisms: [{
            authType:     'BasicAuth',
            usernameAttr: 'dom:name',
            passwordAttr: 'dom:password'
        }]
    },
    helmut: true
});
