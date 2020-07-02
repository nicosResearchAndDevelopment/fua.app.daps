let
    runtime = "PROD",
    tmp
; // top level let

//region process.argv
process['argv']['forEach']((val, index, array) => {

    let
        _argv_property,
        _argv_value
    ;

    if (val['indexOf']("=") !== -1) {
        _argv_property = val['split']("=")[0];
        _argv_value    = val['split']("=")[1];
    } // if()
    switch (_argv_property) {
        case "runtime":
            runtime = _argv_value;
            break;
        default:
            break;
    } // switch()
});
//endregion process.argv

const
    // REM: njs internal modules
    // ALPHA
    crypto       = require('crypto'),
    events       = require("events"),
    fs           = require("fs"),
    os           = require("os"),
    path         = require("path")
    , // REM non-node modules
    express      = require("express"),
    router       = express.Router(),
    request      = require('request'),
    jwt          = require("jsonwebtoken"),
    multiparty   = require("multiparty"),
    redis        = require("redis"),
    //TODO: has to come from calling app by parameter
    TEST         = {
        "0": true
    } // TEST
    , // ORDER!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    appStartedAt = new Date(),
    //TODO: 'runtime' has to come from app.js called with parameter...
    config       = require(`./config/config.js`)({'runtime': /** default: "PROD" */ runtime}),
    str_port     = ((config['port']) ? ((config['port'] === 80) ? "" : `:${config['port']}`) : ""),
    root         = `${config['schema']}://${config['host']}${str_port}/`, //TODO: endstanding '7'?
    lib_path     = (fs.existsSync(`./lib`) ? `./lib` : config['lib_path']),
    hrt          = require(`${lib_path}/core.hrtn/src/core.hrtn${config['js_file_suffix']}`)(),
    uuid         = require(`${lib_path}/core.uuid/src/core.uuid${config['js_file_suffix']}`)({
        'mode':      "local",
        'parameter': {'crypto': crypto}
    }),
    Helmut       = require(`${lib_path}/agent.Helmut/src/agent.Helmut${config['js_file_suffix']}`)(config['Helmut'])['Helmut'],
    namespace    = require(`${lib_path}/core.namespace/src/core.namespace${config['js_file_suffix']}`)({
        'self':   config['self_prefix'],
        'root':   root,
        'config': config['namespace']
    })
    ,
    mime         = require(`${lib_path}/core.mime/src/core.mime${config['js_file_suffix']}`)({
        'config': config['mime']
    })
    ,
    main         = require(`./code/main${config['js_file_suffix']}`),
    name_prefix  = `daps <${config['name']}>`
; // top level const

Helmut['secret'] = "Genau123"; //TODO:config

//region scheduler

let scheduler;

if (config['scheduler'] && config['scheduler']['dop']) {
    config['scheduler']['@id'] = `${root}${((config['scheduler']['path']) ? config['scheduler']['path'] : "scheduler")}`;
    scheduler                  = require(`${lib_path}/module.Scheduler/src/module.Scheduler${config['js_file_suffix']}`)({
        'EventEmitter': events,
        'hrt':          hrt,
        'config':       config['scheduler']
    });
} else {
    console.warn(`${new Date().toISOString()} : ${name_prefix} : scheduler : suppressed by configuration`);
} // if ()

//endregion scheduler

//region persistence

const
    persistence_redis = require(`${lib_path}/module.persistence.redis/src/module.persistence.redis${config['js_file_suffix']}`)({
        'Helmut': Helmut,
        'redis':  redis,
        'hrt':    hrt,
        'config': config['space']['persistence']['redis']
    })
; // const
//region agent_persistence

if (true) {
    const
        agent_persistence = require(`${lib_path}/agent.Persistence/src/agent.Persistence${config['js_file_suffix']}`)({
            'hrt': hrt
        })
    ; // const
    agent_persistence['add_persistence_module']([
        persistence_redis
    ]);
    config['space']['agent_persistence'] = agent_persistence;
    //region data.repository
    //try {
    //    require(`../data/repository/load.js`)({
    //        'agent_persistence': agent_persistence
    //    })
    //} catch (jex) {
    //    jex;
    //} // try
    //endregion data.repository
} // if (shield)

//endregion agent_persistence
//endregion persistence

//region agent.amec
const
    agent_amec = require(`${lib_path}/agent.amec/src/agent.amec${config['js_file_suffix']}`)({
        'hrt':          hrt,
        'auth_modules': [
            require(`${lib_path}/module.auth.basic/src/module.auth.basic${config['js_file_suffix']}`)({
                'Helmut':      Helmut,
                'persistence': persistence_redis,
                'hrt':         hrt
            }),
            require(`${lib_path}/module.auth.idsc/src/module.auth.idsc${config['js_file_suffix']}`)({
                'Helmut':      Helmut,
                'persistence': persistence_redis,
                'hrt':         hrt
            }),
            require(`${lib_path}/module.auth.user/src/module.auth.user${config['js_file_suffix']}`)({
                'Helmut':      Helmut,
                'persistence': persistence_redis,
                'hrt':         hrt
            })
        ] // auth_modules
    }) // agent_amec
; // const

//region TEST agent_amec
if (false) {
    let
        user = {'name': "jott", 'password': "grunz"},
        req  = {}
    ;

    persistence_redis.set(
        {'@id': user['name'], 'user': user['name'], 'password': user['password']},
        true, /** hash_id */
        true, /** encrypt_value */
        10000 /** timeout */
    ).then((result) => {
        result;
        req = {
            'headers': {
                'authorization': `Basic ${Helmut.stringToBase64((`${user['name']}:${user['password']}`))}`
            }
        };
        agent_amec(req, /** mech */ "Basic", /** timeout */ 5000).then((auth) => {
            //req = {
            //    'user': {'name': "jott", 'password': "grunz"}
            //};
            //agent_amec(req, /** mech */ "user", /** timeout */ 5000).then((auth) => {
            console.log(`${new Date().toISOString()} : app.js : agent_amec.then(auth) : <${JSON.stringify(auth, "", "\t")}> `);
            //throw(new Error());
        }).catch((err) => {
            console.log(`${new Date().toISOString()} : app.js : agent_amec.catch(err) : <${JSON.stringify(err, "", "\t")}> `);
            //throw(new Error());
        });
    }).catch((err) => {
        err;
    });
} // if (shield)
//endregion TEST agent_amec

//endregion agent.amec

//region space

config['space']['root']      = root;
config['space']['resources'] = []; // config['space']['resources']

const
    space = require(`${lib_path}/module.Space/src/module.Space${config['js_file_suffix']}`)({
        'hrt':    hrt,
        'config': config['space']
    })
; // const

//endregion space

//region PEP

config['PEP']['scheduler'] = scheduler;
const
    PEP                    = require(`${lib_path}/module.PEP/src/module.PEP${config['js_file_suffix']}`)({
        'name':   name_prefix,
        'hrt':    hrt,
        'config': config['PEP']
    }),
    PEP_events             = []
;

PEP_events.push({
        '@id':      config['PEP']['heartbeat']['@id'],
        'multi':    false,
        'once':     false,
        'exec':     ({'prov': prov, 'event': event, 'parameter': parameter}) => {
            return new Promise((resolve, reject) => {
                let result = {
                        'event': event,
                        'prov':  prov
                    }
                ; // let
                try {
                    console.log(`${new Date().toISOString()} : ${name_prefix} : PEP : event <${config['PEP']['heartbeat']['@id']}> : reached`);
                    //TODO: hrt
                    result['ts'] = Date.now() / 1000;
                    resolve(result);
                } catch (jex) {
                    reject(jex);
                } // try
            }); // return new Promise()
        }, // exec
        'schedule': {
            'uid':   `urn:app:schedule:task:heartbeat`,
            'dop':   true,
            'event': config['PEP']['heartbeat']['@id'],
            'run':   {
                'repeat':     config['PEP']['heartbeat']['dop'],
                'position':   0,
                'onCallback': true,
                'sequence':   [
                    //{'duration': 1},
                    {'duration': config['PEP']['heartbeat']['duration']}
                ]
            }
        }
    }
    //,{
    //    '@id':   "urn:app:event:broadcast:send",
    //    'multi': false,
    //    'once':  false,
    //    'exec':  ({'prov': prov, 'event': event, 'parameter': parameter}) => {
    //        return new Promise((resolve, reject) => {
    //            let result = {
    //                    'event': event,
    //                    'prov':  prov
    //                }
    //            ; // let
    //            try {
    //                console.warn(`${new Date().toISOString()} : PEP : urn:app:event:broadcast:send : reached`);
    //                broadcast['send']({'resource': parameter['resource']}).then((broadcast_result) => {
    //                    broadcast_result;
    //                    result['ts'] = Date.now() / 1000;
    //                    resolve(result);
    //                }).catch((broadcast_err) => {
    //                    reject(broadcast_err);
    //                });
    //            } catch (jex) {
    //                reject(jex);
    //            } // try
    //        }); // return new Promise()
    //    } // exec
    //}

    //,{
    //    '@id':   "urn:event:DEVL:DONOT",
    //    'multi': false,
    //    'once':  false,
    //    'exec':  ({'prov': prov, 'event': event, 'parameter': parameter}) => {
    //        return new Promise((resolve, reject) => {
    //            let result = {'s': true};
    //            try {
    //                result['prov']       = prov;
    //                result['event']      = event;
    //                result['type']       = "fua:Policy";
    //                result['fua:Policy'] = {
    //                    '@context': {
    //                        'action': "odrl:action"
    //                    },
    //                    'type':     "fua:Policy",
    //                    'action':   "DONOT"
    //                };
    //                result['ts']         = Date.now();
    //                resolve(result);
    //            } catch (jex) {
    //                reject({'type': "jex", 'jex': jex});
    //            } // try
    //        })
    //    }
    //}
);

if (false) // urn:event:DEVL:doit
    PEP_events.push(
        {
            '@id':   "urn:event:DEVL:doit",
            'multi': false,
            'once':  false,
            'exec':  ({'prov': prov, 'event': event, 'parameter': parameter}) => {
                return new Promise((resolve, reject) => {
                    let result = {
                            '@context':                    {
                                'odrl': "https://www.w3.org/TR/odrl-model/"
                                //REM: set by PEP.result : 'fua':  "https://www.nicos-rd.com/fua#",
                            },
                            'fua:s':                       true,
                            'fua:prov': prov, 'fua:event': event,
                            'fua:ts':                      undefined,
                            'odrl:Policy':                 {
                                'type':        "odrl:Set",
                                'odrl:action': "use"
                            }
                        }
                    ; // let
                    try {
                        result['fua:ts'] = Date.now();
                        resolve(result);
                    } catch (jex) {
                        reject({'type': "jex", 'jex': jex});
                    } // try
                }); // return new Promise()
            } // exec
        }
    );

//PEP_events = PEP_events.concat(require(`${__dirname}/PRP/space/maintenance/PRP.space.maintenance.js`));
//PEP_events = PEP_events.concat(require(`${__dirname}/PRP/acl/PRP.acl.js`));

PEP['addEvents'](PEP_events);

if (scheduler) {
    scheduler['on']('event', PEP['event']);
} // if ()

PEP.listen((err, result) => {
    //PEP.enforce({'prov': "fua.module.Space.test", '@id': "urn:event:DEVL:DONOT", 'parameter': {}}).then(result => {
    if (TEST['0'] && true) {
        PEP.enforce({
            'prov':      "fua.module.Space.test",
            '@id':       "urn:event:DEVL:doit",
            'parameter': {}
        }).then((result) => {
            console.log(`${new Date().toISOString()} : ${name_prefix} : PEP : @id <${"urn:event:DEVL:doit"}>`);
            //console.log(`PEP.metrics : ${JSON.stringify(global['u']['agent']['PEP'].metrics, "", "\t")}`);
            //console.log(`PEP.registeredEventIds : ${JSON.stringify(global['u']['agent']['PEP'].registeredEventIds, "", "\t")}`);
            //console.log(`PEP.eventMetrics : ${JSON.stringify(global['u']['agent']['PEP'].eventMetrics, "", "\t")}`);
            //console.log(`PEP.enforce : result : ${JSON.stringify(result, "", "\t")}`);
        }).catch((err) => {
            console.error(`${new Date().toISOString()} : ${name_prefix} : PEP : err <${err.toString()}>`);
        });
    } // if (TEST && ???)
}); // PEP.listen()

//endregion PEP

//region daps
config['https_server_options']['key']  = fs['readFileSync'](`${config['https_server_options']['key']}`);
config['https_server_options']['cert'] = fs['readFileSync'](`${config['https_server_options']['cert']}`);
config['self_description']             = fs['readFileSync'](`${config['self_description']}`);
config['jwks']                         = fs['readFileSync'](`${config['jwks_path']}`);
config['connector']['key']             = fs['readFileSync'](`${config['connector']['key']}`);
config['connector']['cert']            = fs['readFileSync'](`${config['connector']['cert']}`);
//endregion daps

//region IDS
//config['client']['DAPS']['request'] = request;
//config['client']['MDB']['request']  = request;
const
    ids_enumeration = require(`${lib_path}/IDS/enumeration/src/ids.enumeration${config['js_file_suffix']}`)({
        'SecurityProfile': true
    }),
    IDS             = {
        'enum':                    ids_enumeration,
        'DAPSclient': /** class */ require(`${lib_path}/IDS/DAPS.client/src/ids.DAPS.client${config['js_file_suffix']}`)({
            'hrt':         hrt,
            'enumeration': ids_enumeration,
            'config':      null // REM: NO instance!!!
        })

        //'MDBclient': /** class */  require(`${lib_path}/IDS/MDB.client/src/ids.MDB.client${config['js_file_suffix']}`)({
        //    'hrt':         hrt,
        //    'enumeration': ids_enumeration,
        //    'config':      null // REM: NO instance!!!
        //})

    } // IDS

; // const
//endregion IDS

const
    IM   = require(`${lib_path}/IM/src/IM${config['js_file_suffix']}`)({
        'hrt':   hrt,
        'uuid':  uuid,
        'space': space
    }),
    DAPS = {
        'router': require(`./code/routes/router.daps${config['js_file_suffix']}`)({
            'router':     router,

            'hrt':        hrt,
            'Helmut':     Helmut,
            'about':      config['self_description'],
            'multipart': require(`${lib_path}/IDS/Multipart/src/ids.Multipart${config['js_file_suffix']}`)({
                'multiparty': multiparty,
                'autoFiles':  false
            }),
            'selfDescribe':      require(`${lib_path}/IDS/SelfDescription.Connector/src/ids.SelfDescription.Connector${config['js_file_suffix']}`)({
                'about':         config['self_description']
            }),
            'jwks':       config['jwks'],
            //'agent':      require(`${lib_path}/IDS/DAPS.agent/src/ids.DAPS.agent${config['js_file_suffix']}`)({
            'agent':      require(`./code/agent.DAPS${config['js_file_suffix']}`)({
                'jwt':         jwt,
                'hrt':         hrt,
                'Helmut':      Helmut,
                'crypto':      crypto,
                'uuid':        uuid,
                'space':       space,
                'private_key': config['connector']['key'],
                'public_cert': config['connector']['cert']
                ,
                'issuer':      root
            })
        })
    }
; // const

//region HTTP
const HTTP = {
    'methods':      {
        'GET':    "GET",
        'Get':    "GET",
        'get':    "GET",
        'OPTION': "OPTION",
        'Option': "OPTION",
        'option': "OPTION",
        'POST':   "POST",
        'Post':   "POST",
        'post':   "POST"
    }, // methods
    'header':       {
        'content-type': "content-type",
        'Content-Type': "content-type"
    },
    'return_codes': {
        200:   {'value': 200},
        '200': {'value': 200}
    } // return_codes
}; // HTTP
//endregion HTTP

//region IM

let
    ontologies_container = [],
    context_path         = undefined// `${root_data}context`
;

let ontologies = [
    'rdf',
    'owl',
    'ldp'
];

ontologies.map((name) => {
    require(`${lib_path}/IM/${name}/src/IM.${name}${config['js_file_suffix']}`)({
        'path':         path,
        'fs':           fs
        ,
        'IM':           IM,
        'hrt':          hrt,
        'uuid':         uuid,
        'space':        space,
        'container':    ontologies_container, // TODO: BasicContainer 'IM'?!?
        'context_path': context_path
    });
});
//space.set(space.get("ldp:BasicContainer")({
//    '@id': `${root_data}ontologies/`,
//    '$nv': true
//}));
//root_container.contains = space.get(`${root_data}ontologies/`);

//endregion IM

//region root / basic container

let root_container = space.get("ldp:BasicContainer")({
    //'@id': `${root_data}`,
    '@id': `1/`,
    '$nv': true
});
space.set(root_container);

////region TEST
//let grunz = root_container['$serialize']({'mode': "json"});
//console.warn(grunz);
//throw new Error();
////endregion TEST

//endregion root / basic container

//region srv

//if (true) {
config['srv']['@id']       = `1/server/`;
config['srv']['root']      = `1/`;
config['srv']['space']     = space;
config['srv']['os']        = os;
config['srv']['hrt']       = hrt;
config['srv']['PEP']       = PEP;
config['srv']['heartbeat'] = {
    'cpu_usage_per_second': 0.1 // TODO: config
};
let srv                    = require(`${lib_path}/agent.Server/src/agent.Server${config['js_file_suffix']}`)(config['srv']);
//} // if (shield)
//endregion srv

//region data
let group_container = space.get("ldp:BasicContainer")({
    '@id':        `1/groups/`,
    'rdfs:label': "groups",
    '$nv':        true
});
space.set(group_container);
root_container['contains'] = group_container;

let group = space.get("rdfs:Resource")({
    '@id':         `1/groups/admin`,
    'rdfs:label':  "admin",
    'rdfs:member': [],
    '$nv':         true
});
space.set(group);
group_container['contains'] = group;
//endregion data

//region TEST data
if ((runtime === "DEVL") && true) {
    space.set({
        '@id':       "53:56:3C:00:6D:86:29:8F:92:22:AF:39:9E:8D:76:A3:20:77:79:78:keyid:3B:9B:8E:72:A4:54:05:5A:10:48:E7:C0:33:0B:87:02:BC:57:7C:A4",
        'publicPem': `-----BEGIN CERTIFICATE-----
MIIE8DCCA9igAwIBAgIBEDANBgkqhkiG9w0BAQUFADBNMQswCQYDVQQGEwJERTER
MA8GA1UECgwIbmljb3MgQUcxDzANBgNVBAsMBklEUy1EQzEaMBgGA1UEAwwRSURT
LURDLUNvbm5lY3RvcnMwHhcNMTgxMDI2MTEzMTQwWhcNMjAxMDI1MTEzMTQwWjBs
MQswCQYDVQQGEwJERTERMA8GA1UECgwIbmljb3MgQUcxFDASBgNVBAsMC0lEUy1E
Qy1EQVBTMTQwMgYDVQQDDCtodHRwOi8vd3d3Lm5pY29zLXJkLmNvbS9JRFMvY29u
bmVjdG9yL2R1bW15MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArScN
3sdWpcfiaEnF/efg7Vts5Zr9XysqvictAAHnklqt/h0wCs/UBw+1b+8z+yat98SU
NtTVdP/JPwia64RPC2d1doTb0ZGj/gLzUaZCzhFIzG6qi9ld3xrwZPWTMdvZUUJL
an3mgGcJHIMbdCf304NvoLR3iEvve+ToYc6CfYsdMTz4gVKRCxHtkonjcL4CIEUs
husXUGmok2tGuoUqOK5Cuyo7ewPRnBzkk3OhO0QfMP4SeWsFF2po7X2XlNCWB4Bv
04Lhd7RK2PiMz/qjq0L7vEFh7Q60b4T2+DzffyifA+5jJtO6UPRzmdyY8xkXbKfi
GdugKsmA1LzW7WQolwIDAQABo4IBujCCAbYwDgYDVR0PAQH/BAQDAgWgMAkGA1Ud
EwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRT
VjwAbYYpj5IirzmejXajIHd5eDAfBgNVHSMEGDAWgBQ7m45ypFQFWhBI58AzC4cC
vFd8pDCBogYIKwYBBQUHAQEEgZUwgZIwWAYIKwYBBQUHMAKGTGh0dHA6Ly93d3cu
aW50ZXJuYXRpb25hbGRhdGFzcGFjZXMub3JnL2RjL0Nvbm5lY3RvcnMvaWRzLWRj
LWNvbm5lY3Rvci1jYS5jZXIwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLWRjLmlu
dGVybmF0aW9uYWxkYXRhc3BhY2VzLm9yZzBdBgNVHR8EVjBUMFKgUKBOhkxodHRw
Oi8vd3d3LmludGVybmF0aW9uYWxkYXRhc3BhY2VzLm9yZy9kYy9Db25uZWN0b3Jz
L2lkcy1kYy1jb25uZWN0b3ItY2EuY3JsMDYGA1UdEQQvMC2GK2h0dHA6Ly93d3cu
bmljb3MtcmQuY29tL0lEUy9jb25uZWN0b3IvZHVtbXkwDQYJKoZIhvcNAQEFBQAD
ggEBAEpGnXkinF7fHNY/j1mhbgLX41fv/rZXIY4OuUceWew0M8LQZpzz3zktacon
ZgDK/PsXyCcv9P//DHNBJynn0Jp0pJiyGl6O+8ltgG36wQ+88DRfdaxDIv458Xx6
Zg55H/HWsT9ulnHzf8sdR8DLesjMYZ0paHDLYeCl1Nhyxsvy74EdmRIao98Qf1fC
NLV9mmMysTmcBhe4drEPgfIH9Ct8SBBWzaqaCP6B0YTzxMvTniW9lurXy0l8Phou
A7XLABbl6rsrlSk2NhY9AdVRmoqlvr3guqqz7ow8KAoPeurSK472+Q205VMzFZQo
LMyKJ4db/YYrxmBEOxhe8tbDpVI=
-----END CERTIFICATE-----`
    });
} // if (shield)
//endregion TEST data

main({
    'name_prefix':    name_prefix,
    'lib_path':       lib_path,
    'config':         config
    //region mode_modules :: node (ALPHA)
    , 'fs':           fs,
    'https':          require("https"),
    'path':           require("path")
    //endregion mode_modules :: node
    //region mode_modules :: third (ALPHA)
    ,
    'bodyParser':     require("body-parser"),
    'cookieParser':   require("cookie-parser"),
    'express':        express,
    //region graphQL
    //'graphql':        require("graphql"),
    //'expressGraphQL': require("express-graphql"),
    //endregion graphQL
    //region gRPC
    //'grpc':                     require("grpc"),
    //'protoLoader':              require("@grpc/proto-loader"),
    //endregion gRPC
    'jsonpath':       require("jsonpath"),
    'jwt':            require("jsonwebtoken"),
    //region mosca
    //'mosca':        require("mosca"),
    //'redis':          redis,
    //endregion mosca
    'request':        request,
    'session':        require("express-session")
    //endregion mode_modules :: third
    //region fua_modules
    ,
    'TEST':           TEST
    ,
    'js_file_suffix': config['js_file_suffix'],
    'hrt':            hrt,
    'uuid':           uuid,
    'namespace':      namespace,
    'mime':           mime,
    'Helmut':         Helmut,
    'agent_amec':     agent_amec
    ,
    'router':         router,
    'srv':            srv,
    'scheduler':      scheduler,
    'space':          space,
    'context_path':   context_path,
    'PEP':            PEP,
    'IDS':            IDS,
    'DAPS':           DAPS
    //endregion fua_modules
}).then((main_result) => {
    let mainThenReachedAt = new Date();
    /** TODO:log */
    console.log(`${(new Date).toISOString()} : ${name_prefix} : boot : appStartedAt      <${appStartedAt}>`);
    console.log(`${(new Date).toISOString()} : ${name_prefix} : boot : mainThenReachedAt <${mainThenReachedAt}>`);
    console.log(`${(new Date).toISOString()} : ${name_prefix} : boot : elapsed time      <${(mainThenReachedAt.valueOf() - appStartedAt.valueOf()) / 1000}sec>`);
    console.log(`${(new Date).toISOString()} : ${name_prefix} : boot : result : <`);
    console.log(JSON.stringify(main_result, "", "\t"));
    console.log(`>`);

    //region TEST
    if ((runtime === "DEVL") && true) {

    } // if (shield)
    //endregion TEST

}).catch((main_err) => {
    console.error(`${(new Date).toISOString()} : ${name_prefix} : error <${main_err.toString()}>`);
}); //main()

