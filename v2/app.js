const
    assert  = require('@nrd/fua.core.assert'),
    is      = require('@nrd/fua.core.is'),
    ts      = require('@nrd/fua.core.ts'),
    tty     = require('@nrd/fua.core.tty'),
    util    = require('@nrd/fua.core.util'),
    express = require('express');

module.exports = async function ({server: {server, app, io}, amec, daps, ...config}) {

    app.use(function (request, response, next) {
        tty.log.request(request);
        next();
    });

    const _requestObserver = {
        ioNamespace: null,
        initializeIO() {
            if (this.ioNamespace) return;
            assert(io, 'expected io to be enabled');
            this.ioNamespace = config.requestObserver?.namespacePath
                ? io.of(config.requestObserver.namespacePath) : io;
            return this;
        },
        normalizeData(target) {
            if (!is.object(target)) return target;
            const objectCache = new WeakSet();
            return JSON.parse(
                JSON.stringify(
                    target,
                    (key, value) => {
                        if (!is.object(value)) return value;
                        if (objectCache.has(value)) return null;
                        objectCache.add(value);
                        return value;
                    }
                    // IDEA use replacer and a WeakMap to handle circular json structures
                ),
                (key, value) => {
                    if (!is.object(value) || is.array(value)) return value;
                    switch (value.type) {
                        case 'Buffer':
                            return Buffer.from(value);
                        default:
                            return value;
                    }
                }
            );
        },
        emitEvent(eventName, ...args) {
            if (!this.ioNamespace) return;
            // this.ioNamespace.emit(eventName, ...args);
            // REM "TypeError: data.hasOwnProperty is not a function" when using pure requestData, maybe fixed in newer socket.io version
            const normalizedArgs = args.map(this.normalizeData.bind(this));
            // REM "TypeError: Converting circular structure to JSON" when adding true to getPeerCertificate to include the certificate chain
            this.ioNamespace.emit(eventName, ...normalizedArgs);
            // REM using JSON parse and stringify to fix socket.io issue is quite inefficient
            return this;
        },
        connectListeners(server) {
            server.on('request', this.onRequest.bind(this));
            // TODO connect other events from request, response and socket
            // SEE https://nodejs.org/api/http.html
            // SEE https://nodejs.org/api/https.html
            // SEE https://nodejs.org/api/net.html
            // SEE https://nodejs.org/api/tls.html
            // SEE https://nodejs.org/api/stream.html
            return this;
        },
        onRequest(request, response) {
            if (request.url.startsWith('/socket.io/')) return;
            this.emitEvent('request', {
                timestamp: ts.dateTime.utc(),
                url:       new URL(request.url, (request.socket.encrypted ? 'https' : 'http') + '://' + request.headers.host),
                method:    request.method,
                headers:   request.headers,
                local:     {
                    address: request.socket.localAddress,
                    port:    request.socket.localPort,
                    family:  request.socket.localFamily,
                    cert:    request.socket.encrypted ? request.socket.getCertificate() : null
                },
                remote:    {
                    address: request.socket.remoteAddress,
                    port:    request.socket.remotePort,
                    family:  request.socket.remoteFamily,
                    cert:    request.socket.encrypted ? request.socket.getPeerCertificate(true) : null
                },
                tls:       request.socket.encrypted ? {
                    auth:  request.socket.authorized || false,
                    error: request.socket.authorizationError || null
                } : null
            });
        },
        onToken(token) {
            this.emitEvent('token', {
                timestamp: ts.dateTime.utc(),
                token, ...daps.decodeToken(token)
            });
        }
    };

    const _default = {
        async jwksRoute(request, response, next) {
            try {
                const body = daps.createJWKS();
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }, // _default.jwksRoute
        async tokenRoute(request, response, next) {
            try {
                assert(request.body, 'expected the request to have a body');
                const param = is.object(request.body) ? {requestParam: request.body} : {requestQuery: request.body};
                const body  = await daps.createDatResponse(param);
                _requestObserver.onToken(body.access_token);
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }, // _default.tokenRoute
        async aboutRoute(request, response, next) {
            try {
                const body = daps.createAbout();
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }, // _default.aboutRoute
        async authRoute(request, response, next) {
            try {
                const auth = await amec.authenticate(request.headers);
                if (!auth) return response.status(401).end();
                response.locals.auth = auth;
                next();
            } catch (err) {
                next(err);
            }
        } // _default.authRoute
    }; // _default

    const _datTweaker = {
        matchers: new Set(), // _datTweaker.matchers
        get(search) {
            assert(is.object(search), 'expected search to be an object');
            const searchKeys = Object.keys(search);
            if (searchKeys.length === 0) return null;
            for (let matcher of this.matchers) {
                const matchKeys = Object.keys(matcher.match);
                if (
                    searchKeys.length === matchKeys.length &&
                    searchKeys.every(key => matchKeys.includes(key)) &&
                    matchKeys.every(key => searchKeys.includes(key))
                ) return matcher;
            }
            return null;
        }, // _datTweaker.get
        set({match, tweak, start, end, count}, override = false) {
            assert(is.object(match) && Object.keys(match).length > 0, 'expected match to be a nonempty object');
            assert(is.null(tweak) || is.object(tweak), 'expected tweak to be a nonempty object');
            assert(is.null(start) || is.number.float.finite(start) || is.string(start), 'expected start to be a timestamp');
            assert(is.null(end) || is.number.float.finite(end) || is.string(end), 'expected end to be a timestamp');
            assert(is.null(count) || is.number.integer(count), 'expected end to be a timestamp');
            let matcher = this.get(match);
            assert(!matcher || override, 'the tweak was already defined');
            if (!matcher) matcher = {match};
            matcher.tweak = tweak || matcher.tweak;
            matcher.start = start ? new Date(ts.dateTime.utc(start)) : matcher.start || new Date(1970, 0);
            matcher.end   = end ? new Date(ts.dateTime.utc(end)) : matcher.end || new Date(1970, 0, 1e8);
            matcher.count = count && count > 0 ? count : matcher.count || Infinity;
            this.matchers.add(matcher);
        }, // _datTweaker.set
        delete(search) {
            const matcher = this.get(search);
            if (!matcher) return false;
            if (matcher) this.matchers.delete(matcher);
            return true;
        }, // _datTweaker.delete
        process(datPayload) {
            const now = new Date();
            for (let matcher of this.matchers) {
                if (matcher.end < now) {
                    this.matchers.delete(matcher);
                    continue;
                }
                if (matcher.start > now)
                    continue;
                if (Object.entries(matcher.match).some(([key, value]) => datPayload[key] !== value))
                    continue;

                for (let [key, value] of Object.entries(matcher.tweak)) {
                    datPayload[key] = value;
                }
                matcher.count--;
                if (matcher.count <= 0) this.matchers.delete(matcher);
            }
        }, // _datTweaker.process
        configure(type, param) {
            assert(is.string(type), 'expected type to be a string');
            switch (type) {
                case 'create':
                    this.set(param, false);
                    return null;
                case 'read':
                    return this.get(param.match);
                case 'update':
                    this.set(param, true);
                    return null;
                case 'delete':
                    this.delete(param.match);
                    return null;
                case 'list':
                    return Array.from(this.matchers);
                default:
                    throw new util.HTTPRequestError(404);
            }
        }, // _datTweaker.configure
        async configRoute(request, response, next) {
            try {
                assert(is.object(request.body), 'expected the request body to be an object');
                const {type, ...param} = request.body;
                const result           = this.configure(type, param);
                if (!result) response.status(200).end();
                else response.type('json').send(JSON.stringify(result));
            } catch (err) {
                if (err instanceof util.HTTPRequestError) response.status(err.status).send(err.statusText);
                else next(err);
            }
        }, // _datTweaker.configRoute
        async tokenRoute(request, response, next) {
            try {
                assert(is.object(request.body) || is.string(request.body),
                    'expected the request body to be an object or a string');

                const
                    param          = is.object(request.body) ? {requestParam: request.body} : {requestQuery: request.body},
                    requestPayload = param.requestPayload = await daps.getDatRequestPayload(param),
                    payload        = param.payload = await daps.createDatPayload(param);

                if (is.object(requestPayload.tweakDat)) {
                    for (let payloadKey of config.tweakDat.pipeTweaks) {
                        if (payloadKey in requestPayload.tweakDat) {
                            if (is.null(requestPayload.tweakDat[payloadKey])) delete payload[payloadKey];
                            else payload[payloadKey] = requestPayload.tweakDat[payloadKey];
                        }
                    }
                }

                if (config.tweakDat.configPath) {
                    this.process(payload);
                }

                const body = await daps.createDatResponse(param);
                _requestObserver.onToken(body.access_token);
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }, // _datTweaker.tokenRoute
        async authRoute(request, response, next) {
            try {
                const auth = response.locals.auth;
                if (!auth) return response.status(401).end();
                // TODO access control for tweak routes
                // if (!auth.access.includes('tweakDat'))
                //     return response.status(401).end();
                next();
            } catch (err) {
                next(err);
            }
        } // _datTweaker.authRoute
    }; // _datTweaker

    if (config.requestObserver)
        _requestObserver.connectListeners(server).initializeIO();

    if (config.jwksPath) app.get(
        config.jwksPath,
        _default.jwksRoute.bind(_default)
    );

    if (config.tokenPath) app.post(
        config.tokenPath,
        express.urlencoded({extended: false}),
        express.text({type: '*/*'}),
        config.tweakDat
            ? _datTweaker.tokenRoute.bind(_datTweaker)
            : _default.tokenRoute.bind(_default)
    );

    if (config.aboutPath) app.get(
        config.aboutPath,
        _default.aboutRoute.bind(_default)
    );

    if (amec) {
        app.use(
            _default.authRoute.bind(_default)
        );

        if (io) io.use(
            (socket, next) => _default.authRoute(socket.request, socket.request.res, next)
        );

        if (config.tweakDat) app.use(
            config.tweakDat.configPath || '/',
            _datTweaker.authRoute.bind(_datTweaker)
        );

        if (io && config.tweakDat) io.of(config.tweakDat.configPath || '/').use(
            (socket, next) => _datTweaker.authRoute(socket.request, socket.request.res, next)
        );
    }

    if (config.tweakDat?.configPath) app.post(
        config.tweakDat.configPath,
        express.json(),
        _datTweaker.configRoute.bind(_datTweaker)
    );

    if (io && config.tweakDat?.configPath) io
        .of(config.tweakDat.configPath)
        .on('connection', (socket) => socket.onAny(util.callbackify(_datTweaker.configure).bind(_datTweaker)))
        .on('connection', (socket) => socket.onAny(util.callbackify(_datTweaker.configure).bind(_datTweaker)));

};
