const
    path               = require('path'),
    fs                 = require('fs/promises'),
    {ExecutionProcess} = require('@nrd/fua.module.subprocess');

initRuntime()
    .then(publishPackage)
    .then(buildImage)
    .then(publishImage)
    .then(exitRuntime)
    .catch(console.error);

async function initRuntime() {
    console.time('done');
    const runtime   = {};
    runtime.cwd     = path.join(__dirname, '..', '..');
    runtime.package = JSON.parse(await fs.readFile(path.join(runtime.cwd, 'package.json')));
    runtime.npm     = ExecutionProcess('npm', {cwd: runtime.cwd, shell: true, verbose: true});
    runtime.docker  = ExecutionProcess('docker', {cwd: runtime.cwd, verbose: true});
    await runtime.npm({version: true});
    await runtime.docker({version: true});
    return runtime;
}

async function exitRuntime(runtime) {
    console.timeEnd('done');
}

async function publishPackage(runtime) {
    // REM npm publish
    await runtime.npm('publish');
    return runtime;
}

async function buildImage(runtime) {
    // REM docker build --no-cache --tag git02.int.nsc.ag:4567/research/fua/registry/fua.app.daps:<version-tag> .
    await runtime.docker('build', {
        'no-cache': true,
        'tag':      `git02.int.nsc.ag:4567/research/fua/registry/fua.app.daps:${runtime.package.version}`
    }, '.');
    return runtime;
}

async function publishImage(runtime) {
    // REM docker push git02.int.nsc.ag:4567/research/fua/registry/fua.app.daps:<version-tag>
    await runtime.docker('push', `git02.int.nsc.ag:4567/research/fua/registry/fua.app.daps:${runtime.package.version}`);
    return runtime;
}
