let
    KEY_MAX_ROW_SIZE = 76,
    connector        = {
        daps:  require('../../cert/connector/client.js'),
        alice: require('./alice/connector.js'),
        bob:   require('./bob/connector.js')
    },
    output           = '';

for (let [name, certs] of Object.entries(connector)) {
    let
        base64KeyValue = certs.pub.toString('base64'),
        base64Output   = '';

    for (let k = 0; k < base64KeyValue.length; k += KEY_MAX_ROW_SIZE) {
        if (k > 0) base64Output += '\n';
        base64Output += base64KeyValue.substring(k, k + KEY_MAX_ROW_SIZE);
    }

    output += 'Base64KeyValue for ' + name + ':\n' + base64Output + '\n\n';
}

console.log(output);
