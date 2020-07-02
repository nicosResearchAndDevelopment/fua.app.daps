module.exports = function ({
                               'jwt':                  jwt,
                               'hrt':                  hrt,
                               'Helmut':               Helmut,
                               'crypto':               crypto,
                               'uuid':                 uuid,
                               'space':                space
                               ,
                               'private_key':          private_key = undefined,
                               'public_cert':          public_cert = undefined
                               ,
                               //header
                               'DAT_header_type':      DAT_header_type = "JWT", // TODO:config
                               'DAT_header_kid':       DAT_header_kid = "default", // TODO:config
                               'DAT_header_algorithm': DAT_header_algorithm = "HS256", // TODO:config
                               'issuer':               issuer,
                               'audience':             audience = "https://w3id.org/idsa/code/IDS_CONNECTORS_ALL", // TODO:config
                               'experation':           experation = Math.round(((new Date).valueOf() / 1000) + (60 * 60 * 24)), // sec
                               'scope':                scope = "ids_connector_attributes" // TODO:config
                           }) {

    const
        StartTime = (Date.now() / 1000.0)
    ; // const
    let
        _model    = null // !!!
    ; // let

    function daps({
                      'client_assertion':         client_assertion,
                      'client_assertion_type':    client_assertion_type,
                      'grant_type':               grant_type,
                      //
                      'requesterPeerCertificate': requesterPeerCertificate
                  }) {

        return new Promise((resolve, reject) => {
            try {

                // ZERO   : get decoded subject
                let decoded_token = jwt['decode'](client_assertion);

                // FIRST  : get it from space
                let identity = space.get(decoded_token['iss']);

                if (identity) {

                    // SECOND : verify incoming requester
                    jwt['verify'](
                        client_assertion,
                        //TODO: und genau dieser public key wir auch aus der DAPS-persistance geholt...
                        //`-----BEGIN CERTIFICATE-----\n${_connector['public_crt']}\n-----END CERTIFICATE-----`,
                        //`${_enum['BEGIN_CERTIFICATE']}${_connector['publicKey']}${_enum['END_CERTIFICATE']}`,
                        `${identity['publicPem']}`,
                        {
                            'algorithms': ["RS256"]
                            , 'maxAge':   1000 //REM: sec, TODO: maxAge >>> config
                        },
                        (err, verified_token) => {

                            let
                                idsuuid
                            ;

                            if (err) {
                                ////TODO: dieser Fehler trat dann wirklich mal auf, nach dem der client
                                //// "SECRET" und nicht "RS256" übergabe!!!
                                //switch (err['name']) {
                                //    case "TokenExpiredError":
                                //        reject({
                                //            'type': "err", 'err': {
                                //                '@type':     "TokenExpiredError",
                                //                'message':   err['message'],
                                //                'expiredAt': err['expiredAt'].toString()
                                //            }
                                //        });
                                //        break; // TokenExpiredError
                                //    default:
                                //        reject({
                                //            'type': "UnspecificError", 'UnspecificError': {}
                                //        });
                                //        break; // default
                                //} // switch(err['name'])
                                reject(err);

                            } else {

                                //idsuuid = (verified['iss'] && (verified['iss'] === subject['CN'])) ? subject['CN'] : undefined;

                                idsuuid = `${verified_token['iss']}`;

                                console.warn(`daps : ${(new Date).toISOString()} : idsuuid : ${idsuuid}`);

                                //if (subjectAltName === idsuuid) {
                                if (idsuuid) {

                                    // THIRD  : make token

                                    let
                                        iat        = Math.round((new Date).valueOf() / 1000),

                                        DAT_header = {
                                            //'type':      DAT_header_type,
                                            'keyid':     DAT_header_kid, //TODO:config kid
                                            'algorithm': DAT_header_algorithm
                                        },
                                        DAT_token  = {
                                            '@context':             "https://w3id.org/idsa/contexts/context.jsonld",
                                            '@type':                "ids:DatPayload"
                                            ,
                                            'iss':                  issuer,
                                            'sub':                  idsuuid,
                                            'exp':                  experation,             // sec
                                            'iat':                  iat,                    // sec
                                            'nbf':                  iat,                    // sec
                                            'aud':                  audience,
                                            //
                                            'scope':                [scope]
                                            ,
                                            'referringConnector':   undefined, // 0..1,
                                            'transportCertsSha256': [] // 0..*
                                            ,
                                            'securityProfile':      "idsc:BASE_CONNECTOR_SECURITY_PROFILE",
                                            'extendedGuarantee':    []
                                        }
                                    ; // let

                                    // FOURTH : sign token
                                    jwt['sign'](
                                        DAT_token,
                                        private_key,
                                        DAT_header,
                                        (err, token) => {
                                            if (err) {
                                                reject({'type': "err", 'err': err});
                                            } else {
                                                //TODO:audit
                                                //TODO:log
                                                // FIFTH  : send DAT
                                                resolve(token);
                                            } // if()
                                        } // cb
                                    ); // jwt.sign
                                } else {
                                    reject({
                                        'type': "err",
                                        's':    false,
                                        'err':  {'m': `subjectAltName '${subjectAltName}' differs from id-uuid '${idsuuid}'`}
                                    });
                                } // if ()
                            } // if ()
                        }); // jwt.verify(body_token)
                } else {
                    reject({'message': `unknown iss <${decoded_token['iss']}>`});
                } // if ()

            } catch (jex) {
                reject(jex);
            } // try
        }); // return
    } // function daps()

    Object.defineProperties(daps, {
        '@id': {'value': `1/daps.agent`}
    });

    return daps;

};