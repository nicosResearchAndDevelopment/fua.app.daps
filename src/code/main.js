module.exports = /** main */({
                                 'name_prefix':    name_prefix = "",
                                 'lib_path':       lib_path = {},
                                 'config':         config = {}
                                 //'dopTEST':                  dopTEST = false,
                                 //'assert':                   assert = null,
                                 //region mode_modules :: node (ALPHA)
                                 , 'fs':           fs = null,
                                 'https':          https = null,
                                 'path':           path = null
                                 //endregion mode_modules :: node (ALPHA)
                                 //region mode_modules :: third (ALPHA)
                                 ,
                                 'bodyParser':     bodyParser = null,
                                 'cookieParser':   cookieParser = null,
                                 'express':        express = null,
                                 //region graphQL
                                 //'graphql':        graphql = null,
                                 //'expressGraphQL': expressGraphQL = null,
                                 //endregion graphQL
                                 //region gRPC
                                 //'grpc':                     require("grpc"),
                                 //'protoLoader':              require("@grpc/proto-loader"),
                                 //endregion gRPC
                                 'jsonpath':       jsonpath = null,
                                 'jwt':            jwt = null,
                                 //region mosca
                                 //'mosca':        mosca = null,
                                 //'redis':        redis = null,
                                 //endregion mosca
                                 //'mqtt':         mqtt = null,
                                 'request':        request = null,
                                 'session':        session = null
                                 //endregion mode_modules :: third (ALPHA)
                                 //region fua_modules
                                 ,
                                 'TEST':           TEST = false
                                 ,
                                 'js_file_suffix': js_file_suffix
                                 ,
                                 'router':         router,
                                 'srv':            srv,
                                 'hrt':            hrt = null,
                                 'uuid':           uuid = null,
                                 'namespace':      namespace = null,
                                 'mime':           mime = null,
                                 'Helmut':         Helmut = null,
                                 'agent_amec':     agent_amec = null,
                                 'space':          space = null,
                                 'context_path':   context_path,
                                 'PEP':            PEP = null,
                                 'IDS':            IDS = null,
                                 'DAPS':            DAPS = null
                             }) => {

    return new Promise((resolve_main, reject_main) => {

        try {

            const
                name   = `${name_prefix} : main`,
                app    = express(),
                server = https.createServer(config['https_server_options'], app)
            ; // main const
            let
                result = {}
            ; // main let

            //region error first
            if (!hrt) throw new Error('main : hrt missing.');
            //endregion error first

            //region app

            app.use(bodyParser['urlencoded']({'extended': true}));
            app.use(bodyParser['json']());
            app.use(cookieParser());
            app.use(session({
                'key':               'user_sid',
                'secret':            `${Math.random()}`,
                'resave':            false,
                'saveUninitialized': false,
                'cookie':            {
                    'expires': 600000
                }
            }));

            app.use('/',
                [
                    //REM: dummy!!!
                    (function (parameter) {
                        return (req, res, next) => {
                            let err = null;
                            try {
                                res['locals'] = {'log': true};
                                next(err);
                            } catch (jex) {
                                err = jex;
                                next(err);
                            } // try
                        }; /// return
                    }({}))
                ],
                DAPS['router'],
                (function (parameter) {
                    //const _helmut = u['core']['Helmut'];
                    return (req, res) => {
                        //TODO: make a core-container end-of-route!
                        res['end']();
                    }; // return
                }({}))
                );

            if (config['server_listen']) {
                /** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : start listening...`);
                server['listen'](config['port'], () => {

                    let address = server['address']();
                    /** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : address <${address['address']}>`);
                    /** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : family  <${address['family']}>`);
                    /** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : port    <${address['port']}>`);
                    /** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : ...listening`);
                    result['ts']     = hrt();
                    result['server'] = {
                        'listening': true,
                        'address':   address['address'],
                        'family':    address['family'],
                        'port':      address['port']
                    };
                    resolve_main(result);
                }); // server['listen']()
            } else {
                /** TODO:log */ console.warn(`${new Date().toISOString()} : ${name} : server : prevented for listening by config`);
                result['ts']     = hrt();
                result['server'] = {
                    'listening': false,
                    //TODO: EXPERIMENTAL : 'listen': server['listen']
                    'listen':    server['listen']
                };
                resolve_main(result);
            } // if ()
            //endregion app

        } catch (jex) { // main
            reject_main(jex);
        } // try main

    }); // return P main

}; // fn => main