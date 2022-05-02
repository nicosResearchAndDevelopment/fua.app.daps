/**
 * app.DAPS.client is the application covering module "ids.DAPS.client". So, app.DAPS.client can be understand
 *
 *
 * @type {module:fs}
 */


const
    fs                       = require("fs"),
    // REM: dummy!
    subject_key_identifier   = "53:56:3C:00:6D:86:29:8F:92:22:AF:39:9E:8D:76:A3:20:77:79:78",
    authority_key_identifier = "keyid:3B:9B:8E:72:A4:54:05:5A:10:48:E7:C0:33:0B:87:02:BC:57:7C:A4",
    skiaki                   = `${subject_key_identifier}:${authority_key_identifier}`
; // const

// REM: keep this runnin'... otherwise unsecure certificates (like this comming from daps-dc) are not allowed :-(
// REM: try it by making this line a comment...
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const
    client = require("C:\\fua\\DEVL\\js\\better\\public\\fua_lib\\IDS\\DAPS.client\\src\\ids.DAPS.client.js")({
        'request':          require("request"),
        'jwt':              require("jsonwebtoken")
        ,
        'hrt':              () => (Date.now() / 1000)
        ,
        'port':             3001,
        'refresh_interval': 10 // sec
        ,
        'config':           {
            'skiaki':               skiaki,
            'protocol':             "http",
            'schema':               "https",
            'host':                 "localhost",
            'port':                 3001
            ,
            'refresh_interval':     10,
            'DATrefreshedCallback': (DAT) => {
                throw new Error(DAT);
            }
            ,
            'jwt_aud':              undefined,
            'jwt_exp_offset':       60 // default in seconds
            ,
            'private_key':          fs['readFileSync'](`./cert/dummy_private.key`),
            'public_cert':          fs['readFileSync'](`./cert/dummy_public.crt`)
        }
    })
; // const

function main({'client': client}) {

    return new Promise((resolve, reject) => {

        try {
            client.getAbout({
                //'mode': "POST" // default
                'mode': "GET",
                'header': {}
            }).then((result) => {
                console.log(`${(new Date).toISOString()} : app.DAPS.client : getAbout : about <...\n${JSON.stringify(result, "", "\t")}\n...>`);
            }).catch((err) => {
                err;
            });

            if (true) {
                client.requestJWKS({'timeout': 5000}).then((result) => {
                    console.log(`${(new Date).toISOString()} : main : pem <...\n${result}...>`);
                    let _default = client.getJWK("default");
                    if (true) {
                        client.requestDAT({
                            'aud':     undefined,
                            'timeout': 5000 // default
                        }).then((result) => {
                            console.log(`${(new Date).toISOString()} : app.DAPS.client : main : DAT <...\n${JSON.stringify(result, "", "\t")}\n...>`);
                            resolve();
                        }).catch((err) => {
                            reject(err);
                        }); // client.requestDAT()
                    } else {
                        resolve();
                    } // if(shield)
                }).catch((err) => {
                    reject(err);
                }); // client.requestJWKS()
            } else {
                if (true) {
                    client.requestDAT({
                        'aud':     undefined
                        ,
                        'timeout': 5000 // default
                    }).then((result) => {
                        console.log(`${(new Date).toISOString()} : app.DAPS.client : main : DAT <...\n${JSON.stringify(result, "", "\t")}\n...>`);
                        resolve();
                    }).catch((err) => {
                        reject(err);
                    }); // client.requestDAT()
                } // if(shield)
            } // if(shield)

        } catch (jex) {
            reject(jex);
        } // try

    }); // return new Promise

} // function main()

main({'client': client}).then((result) => {
    result;
}).catch((err) => {
    err;
});

// EOC -----------------------------------------------------------------------------------------------------------------
