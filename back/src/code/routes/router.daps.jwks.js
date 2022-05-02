module.exports = ({
                      'hrt':    hrt = () => (Date.now() / 1000),
                      'router': router,
                      'Helmut': Helmut,
                      'jwks':  jkws = ""
                  }) => {

    router.get('/.well-known/jwks.json', (req, res) => {
        let
            err = null // !!!
        ;

        //let
        //    result = index
        //        .replace(/__FIR_login_username/, login_username)
        //        .replace(/__FIR_login_password/, login_password)
        //        .replace(/__FIR_urn_lt_login__/, "ANMELDEN")
        //;
        Helmut['tweakHeader']({
            'response': res,
            'set':      [
                ['Content-Type', 'application/json']
            ]
        });

        if (err) {
            //TODO: set header
            res.send();
        } else {
            //res.send(about());
            res.send(jkws);
        } // if ()

    });

    return router;

};
