const
    util    = require('./code/util.daps.js'),
    path    = require('path'),
    express = require('express');

module.exports = async function DAPSApp(
    {
        'config': config,
        'agent':  agent
    }
) {

    const _default = {
        async jwksRoute(request, response, next) {
            try {
                const body = agent.createJWKS();
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        },
        async tokenRoute(request, response, next) {
            try {
                util.assert(request.body, 'expected the request to have a body');
                const param = util.isObject(request.body) ? {requestParam: request.body} : {requestQuery: request.body};
                const body  = await agent.createDatResponse(param);
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        },
        async aboutRoute(request, response, next) {
            try {
                const body = agent.createAbout();
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }
    }; // _default

    const _datTweaker = {
        matchers: new Set(),
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
        },
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
        },
        delete(search) {
            const matcher = this.get(search);
            if (!matcher) return false;
            if (matcher) this.matchers.delete(matcher);
            return true;
        },
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
        },
        async configRoute(request, response, next) {
            try {
                util.assert(util.isObject(request.body), 'expected the request body to be an object');
                const {type, ...param} = request.body;
                util.assert(util.isString(type), 'expected type to be a string');
                switch (type) {
                    case 'create':
                        this.set(param, false);
                        response.status(200).end();
                        break;
                    case 'read':
                        response.type('json').send(JSON.stringify(this.get(param.match)));
                        break;
                    case 'update':
                        this.set(param, true);
                        response.status(200).end();
                        break;
                    case 'delete':
                        this.delete(param.match);
                        response.status(200).end();
                        break;
                    case 'list':
                        response.type('json').send(JSON.stringify(Array.from(this.matchers)));
                        break;
                    default:
                        response.status(404).end();
                }
            } catch (err) {
                next(err);
            }
        },
        async tokenRoute(request, response, next) {
            try {
                util.assert(util.isObject(request.body) || util.isString(request.body),
                    'expected the request body to be an object or a string');

                const
                    param          = util.isObject(request.body) ? {requestParam: request.body} : {requestQuery: request.body},
                    requestPayload = param.requestPayload = await agent.getDatRequestPayload(param),
                    payload        = param.payload = await agent.createDatPayload(param);

                if (util.isObject(requestPayload.tweakDat)) {
                    for (let payloadKey of util.toArray(config.daps.tweakDat.pipeRequestTweaks)) {
                        if (payloadKey in requestPayload.tweakDat) {
                            if (util.isNull(requestPayload.tweakDat[payloadKey])) delete payload[payloadKey];
                            else payload[payloadKey] = requestPayload.tweakDat[payloadKey];
                        }
                    }
                }

                if (config.daps.tweakDat.setupMatcherPath) {
                    this.process(payload);
                }

                const body = await agent.createDatResponse(param);
                response.type('json').send(JSON.stringify(body));
            } catch (err) {
                next(err);
            }
        }
    }; // _datTweaker

    agent.app.get(
        config.daps.jwksPath,
        _default.jwksRoute.bind(_default)
    );

    agent.app.post(
        config.daps.tokenPath,
        express.urlencoded({extended: false}),
        express.text({type: '*/*'}),
        config.daps?.tweakDat
            ? _datTweaker.tokenRoute.bind(_datTweaker)
            : _default.tokenRoute.bind(_default)
    );

    if (config.daps?.tweakDat?.setupMatcherPath)
        agent.app.post(
            config.daps.tweakDat.setupMatcherPath,
            express.json(),
            _datTweaker.configRoute.bind(_datTweaker)
        );

    agent.app.get(
        config.daps.aboutPath,
        _default.aboutRoute.bind(_default)
    );

    await agent.listen();
    util.logText(`daps app is listening at <${agent.url}>`);
    agent.once('closed', () => util.logText('daps app has closed'));

}; // module.exports = DAPSApp
