module.exports = ({
                      'hrt':    hrt = () => (Date.now() / 1000),
                      'router': router,
                      'Helmut': Helmut,
                      'agent':  agent,
                      //config
                      'scope':  scope = "ids_connector_attributes" // "https://w3id.org/idsa/core/Connector"
                  }) => {

    router.post('/token', (req, res) => {

        const
            //assertion     = req['body']['assertion'],
            //decoded_token = jwt['decode'](assertion)
            ////connectorId       = `${decoded_token['iss']}`
            requesterPeerCertificate = req['socket']['getPeerCertificate']()
        ; // const
        let
            err                      = null, // !!!
            //result                   = {
            //    'token': {
            //        'ids-attributes': {}
            //    }
            //},
            locals                   = (req['locals'] || {})
        ; // let

        try {

            Helmut['tweakHeader']({
                'response': res,
                'set':      [
                    ['Content-Type', 'application/json']
                ]
            });

            if (req['body']['scope'] !== scope) {
                throw new Error();
            } else {

                agent({
                    //'assertion':                req['body']['assertion'],
                    'client_assertion':         req['body']['client_assertion'],
                    'client_assertion_type':    req['body']['client_assertion_type'],
                    'grant_type':               req['body']['grant_type'],
                    //
                    'requesterPeerCertificate': requesterPeerCertificate
                }).then((result) => {
                    res.send(result);
                }).catch((err) => {
                    res.send();
                });
                //getConnector(decoded_token['iss']).then((connector) => {
                //    connector;
                //    connector['publicPem'];
                //    jwt['verify'](
                //        assertion,
                //        //TODO: und genau dieser public key wir auch aus der DAPS-persistance geholt...
                //        //`-----BEGIN CERTIFICATE-----\n${_connector['public_crt']}\n-----END CERTIFICATE-----`,
                //        //`${_enum['BEGIN_CERTIFICATE']}${_connector['publicKey']}${_enum['END_CERTIFICATE']}`,
                //        connector['publicPem'],
                //        {
                //            'algorithms': ["RS256"]
                //            , 'maxAge':   1000 //REM: sec, TODO: maxAge >>> config
                //        },
                //        (err_verify, verified) => {
                //
                //            let
                //                idsuuid
                //            ;
                //
                //            if (err_verify) {
                //                //TODO: set header
                //                res.send();
                //            } else {
                //
                //                //idsuuid = (verified['iss'] && (verified['iss'] === subject['CN'])) ? subject['CN'] : undefined;
                //                idsuuid = `${verified['iss']}`;
                //                console.warn(`${(new Date).toISOString()} : daps : idsuuid : ${idsuuid}`);
                //
                //                //if (subjectAltName === idsuuid) {
                //                if (idsuuid) {
                //
                //                //    _get_token({
                //                //        'user': {
                //                //            '@type':     "connector",
                //                //            'connector': {
                //                //                'idsuuid':         idsuuid,
                //                //                //'SecurityProfile': get_IDS_SecurityProfile(subjectAltName)
                //                //                'SecurityProfile': _connector['ids:securityProfile']
                //                //            } // connector
                //                //        }, // user
                //                //        'sub':  verified['sub']
                //                //    }).then((result) => {
                //                //        //console.warn(`daps-dc.oauth.model.memory : _get_token : result : \n ${JSON.stringify(result, "", "\t")}`);
                //                //
                //                //        jwt['sign'](
                //                //            result,
                //                //            private_key,
                //                //            {
                //                //                'algorithm': "RS256"
                //                //            },
                //                //            (err, token) => {
                //                //                if (err) {
                //                //                    reject({'type': "err", 'err': err});
                //                //                } else {
                //                //                    u.agent.audit.push({
                //                //                        'event': "token_request",
                //                //                        'type':  "token",
                //                //                        'token': token
                //                //                    }).then(result => {
                //                //                        resolve({'type': "token", 'token': token});
                //                //                    }).catch((err) => {
                //                //                        reject({
                //                //                            'type': "err",
                //                //                            's':    false,
                //                //                            'err':  err
                //                //                        });
                //                //                    });
                //                //                } // if()
                //                //            } // callback
                //                //        ); // jwt.sign
                //                //
                //                //    }).catch((err) => {
                //                //        reject(err);
                //                //    });
                //                } else {
                //                    //TODO: set header
                //                    res.send();
                //                } // if ()
                //            } // if ()
                //        }); // jwt.verify(body_token)
                //}).catch((err) => {
                //    err;
                //});
                //switch (req['body']['client_assertion_type']) {
                //    case "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
                //        //daps.token({
                //        //    'private_key':           __key,
                //        //    //'requester_assertion':  locals_['request']['body']['assertion'],
                //        //    'assertion':             locals_['request']['body']['assertion'],
                //        //    'client_assertion':      locals_['request']['body']['client_assertion'],
                //        //    'client_assertion_type': locals_['request']['body']['client_assertion_type'],
                //        //    'grant_type':            locals_['request']['body']['grant_type'],
                //        //    'requester_public_key':  locals_['request']['public_key']
                //        //}).then((result) => {
                //        //    locals_['public_cert'] = __cert;
                //        //    locals_['token']       = result[result['type']];
                //        //    result_['locals']      = locals_;
                //        //
                //        //    result_['@type'] = "token";
                //        //    result_['token'] = locals_['token'];
                //        //    //region TEST
                //        //    //let
                //        //    //    client_jwt    = require("jsonwebtoken"),
                //        //    //    decoded
                //        //    //;
                //        //    //decoded           = client_jwt.decode(result_['token']);
                //        //    //console.log(`${path_} : u.agent.daps.token : decoded : ${JSON.stringify(decoded, "", "\t")}`);
                //        //    //region TEST
                //        //    result_['s'] = true;
                //        //    resolve(result_);
                //        //
                //        //}).catch((err) => {
                //        //
                //        //    result_['s'] = false;
                //        //
                //        //    switch (err['type']) {
                //        //        case "err":
                //        //            result_['@type'] = "err";
                //        //            result_['err']   = err['err'];
                //        //            resolve(result_);
                //        //            break;
                //        //        default:
                //        //            //REM: so, maybe an esception, not shown to user...
                //        //            reject(err);
                //        //            break;
                //        //    } // switch()
                //        //
                //        //});
                //        break; // "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                //    default:
                //        //reject({'@type': "err", 'err': err});
                //        break; // default
                //} // switch(client_assertion_type)
            } // if ()

            //Helmut['tweakHeader']({
            //    'response': res,
            //    'set':      [
            //        ['Content-Type', 'application/json']
            //    ]
            //});

            //if (err) {
            //    //TODO: set header
            //    res.send();
            //} else {
            //    result['token']['ids-attributes']['ts'] = hrt();
            //    res.send(result);
            //} // if ()

        } catch (jex) {
            err = true;
            //TODO: set header
            res.send();
        } // try
    });

    return router;

};
