module.exports = ({
                      'jwt':    jwt,
                      'router': router,
                      'Helmut': Helmut,
                      'daps':   daps,
                      'about':  about
                  }) => {
    require(`./router.daps.about.js`)({'router': router, 'Helmut': Helmut, 'daps': daps, 'about': about});
    require(`./router.daps.pem.js`)({'router': router, 'Helmut': Helmut, 'daps': daps});
    require(`./router.daps.token.js`)({'router': router, 'Helmut': Helmut, 'daps': daps, 'jwt': jwt});
    return router;
};
