module.exports = ({
                      'multipart':    multipart,
                      'hrt':          hrt = () => (Date.now() / 1000),
                      'router':       router,
                      'Helmut':       Helmut,
                      'about':        about = {},
                      'selfDescribe': selfDescribe,
                      'path':         path = "/about"
                  }) => {

    //region fn
    //endregion fn

    router.post("/", (req, res) => {
        multipart['resolve'](req).then((result) => {
            switch (result['header']['@type']) {
                case "ids:DescriptionRequestMessage":
                    Helmut['tweakHeader']({
                        'response': res,
                        'set':      [['Content-Type', 'application/json']]
                    });
                    res.send(selfDescribe());
                    break;
                default:
                    res.send();
                    break; // default
            } // switch()
        }).catch((err) => {
            res.send();
        }); // resolveMultipart(req)
    }); // router.post("/")

    router.get(path, (req, res) => {
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
            res.send(about);
        } // if ()

    }); // router.get(path)

    return router;

};
