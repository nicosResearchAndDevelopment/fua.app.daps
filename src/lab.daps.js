const
    util = require('./code/util.daps.js');

module.exports = async function DAPSLab(
    {
        'config': config,
        'agent':  agent
    }
) {

    const
        daps_jwks = await agent.generateJWKS();

    console.log('JWKS:', daps_jwks);

    const
        alice_skiaki     = 'D3:64:3F:3B:D0:3A:0B:01:FE:8E:5D:C5:F3:97:B3:E2:8D:40:3D:25:keyid:B2:86:93:B9:34:0F:6F:CA:D4:1A:C0:3E:C6:BF:E1:A0:A0:D0:ED:5E',
        alica_datRequest = {sub: alice_skiaki},
        alica_datHeader  = agent.createDatHeader(alica_datRequest),
        alice_datPayload = await agent.createDatPayload(alica_datRequest),
        alice_dat        = await agent.createDat(alica_datHeader, alice_datPayload);

    console.log('DAT:', {
        request: alica_datRequest,
        header:  alica_datHeader,
        payload: alice_datPayload,
        token:   alice_dat
    });

    process.exit(0);

}; // module.exports = DAPSLab
