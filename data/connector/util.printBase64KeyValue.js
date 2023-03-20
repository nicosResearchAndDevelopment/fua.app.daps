let
    KEY_MAX_ROW_SIZE = 76,
    input            = {
        daps:  require('../server/cert/connector/client.js').key,
        alice: require('./alice/connector.js').pub,
        bob:   require('./bob/connector.js').pub
    },
    output           = '';

for (let [keyName, keyBuffer] of Object.entries(input)) {
    let
        base64KeyValue = keyBuffer.toString('base64'),
        base64Output   = '';

    for (let k = 0; k < base64KeyValue.length; k += KEY_MAX_ROW_SIZE) {
        if (k > 0) base64Output += '\n';
        base64Output += base64KeyValue.substring(k, k + KEY_MAX_ROW_SIZE);
    }

    output += 'Base64KeyValue for ' + keyName + ':\n' + base64Output + '\n\n';
}

console.log(output);
