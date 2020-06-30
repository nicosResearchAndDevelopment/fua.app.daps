module.exports = ({
                      'hrt':    hrt = () => (Date.now() / 1000),
                      'router': router,
                      'Helmut': Helmut
                  }) => {

    router.get('/browse', (req, res) => {
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
                ['Content-Type', 'text/html']
            ]
        });
        if (err) {
            //TODO: set header
            res.send(`<HTML>t.f.h.s. rulez! ERROR <${err.toString()}></HTML>`);
        } else {
            res.send(`<HTML>t.f.h.s. rulez!</HTML>`);
        } // if ()

    }); // router.get()

    return router;
};
