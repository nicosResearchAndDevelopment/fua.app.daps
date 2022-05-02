module.exports = ({
                      'hrt':          hrt = () => (new Date).valueOf() / 1000,
                      'Helmut':       Helmut,
                      'agent':        agent,
                      'router':       router,
                      'about':        about,
                      'selfDescribe': selfDescribe,
                      'jwks':         jwks,
                      'multipart':    multipart
                  }) => {
    require(`./router.daps.about.js`)({
        'router':       router,
        'Helmut':       Helmut,
        'about':        about,
        'selfDescribe': selfDescribe,
        'multipart':    multipart
    });

    require(`./router.daps.jwks.js`)({
        'router': router,
        'Helmut': Helmut,
        'jwks':   jwks
    });

    //require(`./router.daps.pem.js`)({'router': router, 'Helmut': Helmut, 'daps': daps});
    require(`./router.daps.token.js`)({
        'hrt':    hrt,
        'router': router,
        'Helmut': Helmut,
        'agent':  agent
    });
    return router;
};
