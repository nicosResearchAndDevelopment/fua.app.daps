const config = {
          'DEVL': {
              'mode':                 "DEVL",
              'js_file_suffix':       ".js",
              //'js_file_suffix':        ".min.js",
              'name':                 "jott.dt",
              'lib_path':             "C:\\fua\\DEVL\\js\\better\\public\\fua_lib"
              //
              ,
              'self_prefix':          "daps",
              'namespace':            {
                  'fua':     {'prefix': "fua", 'uri': "https://www.nicos-rd.com/", 'vocab': "/"},    // 0
                  //ALPHA
                  'dc':      {'prefix': "dc", 'uri': "http://purl.org/dc/elements/1.1/", 'vocab': "/"},
                  'dcterms': {'prefix': "dcterms", 'uri': "http://purl.org/dc/terms/", 'vocab': "/"},
                  'foaf':    {'prefix': "foaf", 'uri': "http://purl.org/dc/elements/1.1/", 'vocab': "/"},
                  'ids':     {'prefix': "foaf", 'uri': "https://w3id.org/idsa/core/", 'vocab': "/"},
                  'idsm':    {'prefix': "foaf", 'uri': "https://w3id.org/idsa/metamodel/", 'vocab': "/"},
                  'ldp':     {'prefix': "ldp", 'uri': "http://www.w3.org/ns/ldp#", 'vocab': "#"},
                  'owl':     {'prefix': "owl", 'uri': "http://www.w3.org/2002/07/owl#", 'vocab': "#"},
                  'rdf':     {'prefix': "rdf", 'uri': "http://www.w3.org/1999/02/22-rdf-syntax-ns#", 'vocab': "#"},
                  'rdfs':    {'prefix': "rdfs", 'uri': "http://www.w3.org/2000/01/rdf-schema#", 'vocab': "#"},
                  'vann':    {'prefix': "vann", 'uri': "http://purl.org/vocab/vann/", 'vocab': "/"},
                  'vs':      {'prefix': "vs", 'uri': "http://www.w3.org/2003/06/sw-vocab-status/ns#", 'vocab': "#"},
                  'xsd':     {'prefix': "xsd", 'uri': "http://www.w3.org/2001/XMLSchema#", 'vocab': "#"}
              },
              'mime':                 {},
              'schema':               "https",
              'host':                 "localhost",
              'port':                 3001,
              'Helmut':               {
                  'html_replaceHeader': [["X-Powered-By", "nicos Research & Development"]],
                  'html_removeHeader':  ["X-Powered-By"]
              }
              ,
              'srv':                  {},
              'daps_root':            "daps/",
              'inbox':                {'dop': true},
              'space':                {
                  'persistence': {
                      'redis': {
                          'client': {
                              'host': "192.168.178.43",
                              'port': 6379
                          }
                      }
                  }
              },
              'scheduler':            {
                  'dop':              true,
                  'path': /** root */ "/scheduler"
              },
              'PEP':                  {
                  'heartbeat': {
                      '@id':      "urn:PEP:heartbeat",
                      'dop':      true,
                      //REM: undefined OR <= 0, suppress
                      'duration': 60
                  }
              }
              ,
              //'server_listen':        true,
              'server_listen':        true,
              'connector':            {
                  'key':  "./cert/con_private.key",
                  'cert': "./cert/con_public.crt"
              },
              'https_server_options': {
                  'key':                "./cert/tls_private.key",
                  'cert':               "./cert/tls_public.crt", //fs['readFileSync'](`${__dirname}/cert/public.crt`),
                  //'ca':                 fs['readFileSync'](`${__dirname}${config['ca_cert']}`),
                  //
                  'requestCert':        false, //TODO: 'true' :: beim ersten Browser-Aufruf wird auch dort ein Zertifikat angefordert...
                  'rejectUnauthorized': false
              }, // https_server_options
              'self_description':     "./resources/about.json",
              'jwks_path':                  "./cert/jwks.json"
              //TODO: check in app.js if present!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
              //'root_file_system_path': "C:\\fua\\DEVL\\js\\better\\app\\TEST\\data\\gbx"
              ,
              'client':               {} // client
          }, // DEVL
          'PROD': {
              'mode':                 "DEVL",
              'js_file_suffix':       ".js",
              //'js_file_suffix':        ".min.js",
              'name':                 "jott.docker",
              'lib_path':             "C:\\fua\\DEVL\\js\\better\\public\\fua_lib"
              //
              ,
              'self_prefix':          "gbx",
              'namespace':            {
                  'fua':     {'prefix': "fua", 'uri': "https://www.nicos-rd.com/", 'vocab': "/"},    // 0
                  //ALPHA
                  'dc':      {'prefix': "dc", 'uri': "http://purl.org/dc/elements/1.1/", 'vocab': "/"},
                  'dcterms': {'prefix': "dcterms", 'uri': "http://purl.org/dc/terms/", 'vocab': "/"},
                  'foaf':    {'prefix': "foaf", 'uri': "http://purl.org/dc/elements/1.1/", 'vocab': "/"},
                  'ids':     {'prefix': "foaf", 'uri': "https://w3id.org/idsa/core/", 'vocab': "/"},
                  'idsm':    {'prefix': "foaf", 'uri': "https://w3id.org/idsa/metamodel/", 'vocab': "/"},
                  'ldp':     {'prefix': "ldp", 'uri': "http://www.w3.org/ns/ldp#", 'vocab': "#"},
                  'owl':     {'prefix': "owl", 'uri': "http://www.w3.org/2002/07/owl#", 'vocab': "#"},
                  'rdf':     {'prefix': "rdf", 'uri': "http://www.w3.org/1999/02/22-rdf-syntax-ns#", 'vocab': "#"},
                  'rdfs':    {'prefix': "rdfs", 'uri': "http://www.w3.org/2000/01/rdf-schema#", 'vocab': "#"},
                  'vann':    {'prefix': "vann", 'uri': "http://purl.org/vocab/vann/", 'vocab': "/"},
                  'vs':      {'prefix': "vs", 'uri': "http://www.w3.org/2003/06/sw-vocab-status/ns#", 'vocab': "#"},
                  'xsd':     {'prefix': "xsd", 'uri': "http://www.w3.org/2001/XMLSchema#", 'vocab': "#"}
              },
              'mime':                 {},
              'schema':               "https",
              'host':                 "localhost",
              'port':                 3001,
              'Helmut':               {
                  'html_replaceHeader': [["X-Powered-By", "nicos Research & Development"]],
                  'html_removeHeader':  ["X-Powered-By"]
              }
              ,
              'srv':                  {},
              'daps_root':            "daps/",
              'inbox':                {'dop': true},
              'space':                {
                  'persistence': {
                      'redis': {
                          'client': {
                              'host': "192.168.178.43",
                              'port': 6379
                          }
                      }
                  }
              },
              'scheduler':            {
                  'dop':              true,
                  'path': /** root */ "/scheduler"
              },
              'PEP':                  {
                  'heartbeat': {
                      '@id':      "urn:PEP:heartbeat",
                      'dop':      true,
                      //REM: undefined OR <= 0, suppress
                      'duration': 60
                  }
              }
              ,
              //'server_listen':        true,
              'server_listen':        true,
              'connector':            {
                  'key':  "./cert/con_private.key",
                  'cert': "./cert/con_public.crt"
              },
              'https_server_options': {
                  'key':                "./cert/tls_private.key",
                  'cert':               "./cert/tls_public.crt", //fs['readFileSync'](`${__dirname}/cert/public.crt`),
                  //'ca':                 fs['readFileSync'](`${__dirname}${config['ca_cert']}`),
                  //
                  'requestCert':        false, //TODO: 'true' :: beim ersten Browser-Aufruf wird auch dort ein Zertifikat angefordert...
                  'rejectUnauthorized': false
              }, // https_server_options
              'self_description':     "./resources/about.json",
              'pem':                  "./cert/public.pem"
              //TODO: check in app.js if present!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
              //'root_file_system_path': "C:\\fua\\DEVL\\js\\better\\app\\TEST\\data\\gbx"
              ,
              'client':               {} // client
          } // PROD
      }
; // const

module.exports = ({'runtime': runtime = "PROD"}) => {

    runtime = runtime.toUpperCase();

    let
        config_ = config[runtime]
    ;

    //REM: error first
    if (!config_)
        throw new Error(`config : misses given runtime <${runtime}>`);
    if (config_['mode'] !== runtime)
        throw new Error(`config.mode <${config_['mode']}> differs from runtime <${runtime}>`);
    if (runtime === "PROD")
        config_['server_listen'] = true;
    if (!config_['@id'])
        config_['@id'] = `${config_['schema']}://${config_['host']}:${config_['port']}/config`;

    return JSON.parse(JSON.stringify(config_));

}; // module.exports