#!/usr/bin/env node

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

(async function healthcheck() {
    const response = await fetch('http://localhost:3000/', {method: 'HEAD'});
    if (!response.ok) throw new Error(`[${response.status}] ${response.statusText}`);
})().then(function healthy() {
    console.log('healthcheck passed');
    process.exit(0);
}).catch(function unhealthy(err) {
    console.error(err?.stack ?? err);
    process.exit(1);
});
