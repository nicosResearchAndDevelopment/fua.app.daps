const
    util    = require('./code/util.daps.js'),
    express = require('express');

module.exports = async function DAPSApp(
    {
        'config': config,
        'agent':  agent
    }
) {

    util.assert(agent.app, 'expected app to be enabled');

    const _requestObserver = {
        ioNamespace: null,
        initializeIO() {
            if (this.ioNamespace) return;
            util.assert(agent.io, 'expected io to be enabled');
            this.ioNamespace = config.requestObserver?.namespacePath
                ? agent.io.of(config.requestObserver.namespacePath)
                : agent.io;
            return this;
        },
        normalizeData(target) {
            if (!util.isObject(target)) return target;
            const objectCache = new WeakSet();
            return JSON.parse(
                JSON.stringify(
                    target,
                    (key, value) => {
                        if (!util.isObject(value)) return value;
                        if (objectCache.has(value)) return null;
                        objectCache.add(value);
                        return value;
                    }
                    // IDEA use replacer and a WeakMap to handle circular json structures
                ),
                (key, value) => {
                    if (!util.isObject(value) || util.isArray(value)) return value;
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
                created: util.dateTime(),
                url:     new URL(request.url, (request.socket.encrypted ? 'https' : 'http') + '://' + request.headers.host),
                method:  request.method,
                headers: request.headers,
                local:   {
                    address: request.socket.localAddress,
                    port:    request.socket.localPort,
                    family:  request.socket.localFamily,
                    cert:    request.socket.encrypted ? request.socket.getCertificate() : null
                },
                remote:  {
                    address: request.socket.remoteAddress,
                    port:    request.socket.remotePort,
                    family:  request.socket.remoteFamily,
                    cert:    request.socket.encrypted ? request.socket.getPeerCertificate(true) : null
                },
                tls:     request.socket.encrypted ? {
                    auth:  request.socket.authorized || false,
                    error: request.socket.authorizationError || null
                } : null
            });
        },
        onToken(token) {
            this.emitEvent('token', {
                created: util.dateTime(),
                token,
                ...util.decodeToken(token)
            });
        }
    };

    const _default = {
        async jwksRoute(request, response, next) {
            try {
                const body = agent.createJWKS();
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }, // _default.jwksRoute
        async tokenRoute(request, response, next) {
            try {
                util.assert(request.body, 'expected the request to have a body');
                const param = util.isObject(request.body) ? {requestParam: request.body} : {requestQuery: request.body};
                const body  = await agent.createDatResponse(param);
                _requestObserver.onToken(body.access_token);
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }, // _default.tokenRoute
        async aboutRoute(request, response, next) {
            try {
                const body = agent.createAbout();
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }, // _default.aboutRoute
        async authRoute(request, response, next) {
            try {
                const auth = await agent.amec.authenticate(request.headers);
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
            util.assert(util.isObject(search), 'expected search to be an object');
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
            util.assert(util.isObject(match) && Object.keys(match).length > 0, 'expected match to be a nonempty object');
            util.assert(util.isNull(tweak) || util.isObject(tweak), 'expected tweak to be a nonempty object');
            util.assert(util.isNull(start) || util.isFiniteNumber(start) || util.isString(start), 'expected start to be a timestamp');
            util.assert(util.isNull(end) || util.isFiniteNumber(end) || util.isString(end), 'expected end to be a timestamp');
            util.assert(util.isNull(count) || util.isInteger(count), 'expected end to be a timestamp');
            let matcher = this.get(match);
            util.assert(!matcher || override, 'the tweak was already defined');
            if (!matcher) matcher = {match};
            matcher.tweak = tweak || matcher.tweak;
            matcher.start = start ? new Date(util.utcDateTime(start)) : matcher.start || new Date(1970, 0);
            matcher.end   = end ? new Date(util.utcDateTime(end)) : matcher.end || new Date(1970, 0, 1e8);
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
            util.assert(util.isString(type), 'expected type to be a string');
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
                util.assert(util.isObject(request.body), 'expected the request body to be an object');
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
                util.assert(util.isObject(request.body) || util.isString(request.body),
                    'expected the request body to be an object or a string');

                const
                    param          = util.isObject(request.body) ? {requestParam: request.body} : {requestQuery: request.body},
                    requestPayload = param.requestPayload = await agent.getDatRequestPayload(param),
                    payload        = param.payload = await agent.createDatPayload(param);

                if (util.isObject(requestPayload.tweakDat)) {
                    for (let payloadKey of util.toArray(config.tweakDat.pipeTweaks)) {
                        if (payloadKey in requestPayload.tweakDat) {
                            if (util.isNull(requestPayload.tweakDat[payloadKey])) delete payload[payloadKey];
                            else payload[payloadKey] = requestPayload.tweakDat[payloadKey];
                        }
                    }
                }

                if (config.tweakDat.configPath) {
                    this.process(payload);
                }

                const body = await agent.createDatResponse(param);
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
                // if (!util.toArray(auth.access).includes('tweakDat'))
                //     return response.status(401).end();
                next();
            } catch (err) {
                next(err);
            }
        } // _datTweaker.authRoute
    }; // _datTweaker

    if (config.requestObserver)
        _requestObserver.connectListeners(agent.server).initializeIO();

    if (config.jwksPath) agent.app.get(
        config.jwksPath,
        _default.jwksRoute.bind(_default)
    );

    if (config.tokenPath) agent.app.post(
        config.tokenPath,
        express.urlencoded({extended: false}),
        express.text({type: '*/*'}),
        config.tweakDat
            ? _datTweaker.tokenRoute.bind(_datTweaker)
            : _default.tokenRoute.bind(_default)
    );

    if (config.aboutPath) agent.app.get(
        config.aboutPath,
        _default.aboutRoute.bind(_default)
    );

    if (agent.amec) {
        agent.app.use(
            _default.authRoute.bind(_default)
        );

        if (agent.io) agent.io.use(
            (socket, next) => _default.authRoute(socket.request, socket.request.res, next)
        );

        if (config.tweakDat) agent.app.use(
            config.tweakDat.configPath || '/',
            _datTweaker.authRoute.bind(_datTweaker)
        );

        if (agent.io && config.tweakDat) agent.io.of(config.tweakDat.configPath || '/').use(
            (socket, next) => _datTweaker.authRoute(socket.request, socket.request.res, next)
        );
    }

    if (config.tweakDat?.configPath) agent.app.post(
        config.tweakDat.configPath,
        express.json(),
        _datTweaker.configRoute.bind(_datTweaker)
    );

    if (agent.io && config.tweakDat?.configPath) agent.io
        .of(config.tweakDat.configPath)
        .on('connection', (socket) => socket.onAny(util.callbackify(_datTweaker.configure).bind(_datTweaker)));

    await agent.listen();
    util.logText(`daps app is listening at <${agent.url}>`);
    agent.once('closed', () => util.logText('daps app has closed'));

}; // module.exports = DAPSApp
