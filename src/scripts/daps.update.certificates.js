const
    path = require('path'),
    fs   = require('fs/promises');

async function copyCertFiles(source, target) {
    const targetDir = path.dirname(target), targetName = path.basename(target);
    await fs.mkdir(targetDir, {recursive: true});
    for (let targetFile of await fs.readdir(targetDir)) {
        if (!targetFile.startsWith(targetName + '.')) continue;
        const targetPath = path.join(targetDir, targetFile);
        await fs.rm(targetPath);
    }
    const sourceDir = path.dirname(source), sourceName = path.basename(source);
    for (let sourceFile of await fs.readdir(sourceDir)) {
        if (!sourceFile.startsWith(sourceName + '.')) continue;
        const sourcePath = path.join(sourceDir, sourceFile);
        const targetPath = path.join(targetDir, sourceFile.replace(sourceName, targetName));
        await fs.copyFile(sourcePath, targetPath);
    }
}

const
    ca_testbed       = path.join(process.env.FUA_JS_APP, 'nrd-ca', 'resources', 'nrd-testbed'),
    daps_root        = path.join(process.env.FUA_JS_APP, 'daps'),
    copyTestbedCerts = (source, target) => copyCertFiles(path.join(ca_testbed, source), path.join(daps_root, target));

Promise.all([
    copyTestbedCerts('ec/ids/component/daps_nrd/connector/client', 'data/server/cert/connector/client'),
    copyTestbedCerts('ec/ids/component/daps_nrd/tls-server/server', 'data/server/cert/tls-server/server'),
    copyTestbedCerts('ec/ids/component/alice/connector/client', 'test/alice-cert/connector/client'),
    copyTestbedCerts('ec/ids/component/alice/tls-server/server', 'test/alice-cert/tls-server/server')
]).then(() => console.log('done')).catch(console.error);
