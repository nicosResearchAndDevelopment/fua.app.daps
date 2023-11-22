const
    util      = require('./code/util.daps.js'),
    labConfig = {
        skipAll:        true,
        createJWKS:     false,
        createAliceDAT: false,
        createBobDAT:   false,
        exitProcess:    false
    };

module.exports = async function DAPSLab(
    {
        'config': config,
        'agent':  agent
    }
) {

    if (labConfig.skipAll) {
        return;
    }

    if (labConfig.createJWKS) {
        const
            daps_jwks = agent.createJWKS();

        util.logText('DAPS jwks.json');
        util.logObject(daps_jwks);
    }

    if (labConfig.createAliceDAT) {
        const
            alice_skiaki     = 'D3:64:3F:3B:D0:3A:0B:01:FE:8E:5D:C5:F3:97:B3:E2:8D:40:3D:25:keyid:B2:86:93:B9:34:0F:6F:CA:D4:1A:C0:3E:C6:BF:E1:A0:A0:D0:ED:5E',
            alice_datRequest = {sub: alice_skiaki},
            alice_datHeader  = agent.createDatHeader(),
            alice_datPayload = await agent.createDatPayload({requestPayload: alice_datRequest}),
            alice_dat        = await agent.createDat({header: alice_datHeader, payload: alice_datPayload});

        util.logText('Alice DAT');
        util.logObject({
            request: alice_datRequest,
            header:  alice_datHeader,
            payload: alice_datPayload,
            token:   alice_dat
        });
    }

    if (labConfig.createBobDAT) {
        const
            bob_skiaki      = '5D:6C:64:09:0B:BA:54:D8:B4:77:AD:24:12:8B:4A:9F:22:96:F7:91:keyid:B2:86:93:B9:34:0F:6F:CA:D4:1A:C0:3E:C6:BF:E1:A0:A0:D0:ED:5E',
            bob_datRequest  = {sub: bob_skiaki},
            bob_datResponse = await agent.createDatResponse({requestPayload: bob_datRequest});

        util.logText('Bob DAT');
        util.logObject(bob_datResponse);
    }

    if (labConfig.exitProcess) {
        process.exit(0);
    }

}; // module.exports = DAPSLab
