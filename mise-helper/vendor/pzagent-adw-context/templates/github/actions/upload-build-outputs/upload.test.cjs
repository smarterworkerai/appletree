'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {upload} = require('./upload.cjs');

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'component-upload-'));
  t.after(() => fs.rm(root, {recursive: true, force: true}));
  const data = {schema_version: '1.0.0', source_sha: 'a'.repeat(40), components: {}};
  for (const component of ['web', 'worker']) {
    const relative = component + '/build-output.tar.gz'; const file = path.join(root, relative);
    await fs.mkdir(path.dirname(file)); await fs.writeFile(file, component);
    data.components[component] = {path: relative, size: component.length,
      sha256: createHash('sha256').update(component).digest('hex')};
  }
  const manifest = path.join(root, 'upload-manifest.json');
  const save = () => fs.writeFile(manifest, JSON.stringify(data)); await save();
  const calls = [];
  const client = {uploadArtifact: async (...args) => {
    calls.push(args); return {id: calls.length, digest: 'b'.repeat(64), size: 123};
  }};
  return {root, data, save, calls, client, args: {manifest, sourceSha: data.source_sha, runId: '12', runAttempt: '2', client}};
}

test('uploads independent native ZIP artifacts with exact source/run/attempt/component names', async t => {
  const f = await fixture(t); const result = await upload(f.args);
  assert.deepEqual(Object.keys(result), ['web', 'worker']);
  for (const [index, component] of ['web', 'worker'].entries()) {
    const [name, files, root, options] = f.calls[index];
    assert.equal(name, `adw-build-${f.data.source_sha}-12-2-${component}`);
    assert.deepEqual(files, [path.join(f.root, component, 'build-output.tar.gz')]);
    assert.equal(root, path.join(f.root, component));
    assert.deepEqual(options, {retentionDays: 7, compressionLevel: 0, skipArchive: false});
    assert.equal(result[component].archive_sha256, f.data.components[component].sha256);
    assert.equal(result[component].digest, 'sha256:' + 'b'.repeat(64));
  }
});

test('invalid or damaged later component prevents every upload', async t => {
  for (const damage of ['sha', 'size', 'path', 'component', 'symlink', 'source', 'empty']) {
    const f = await fixture(t);
    if (damage === 'sha') f.data.components.worker.sha256 = 'c'.repeat(64);
    if (damage === 'size') f.data.components.worker.size++;
    if (damage === 'path') f.data.components.worker.path = '../outside';
    if (damage === 'component') f.data.components['../escape'] = f.data.components.worker;
    if (damage === 'source') f.data.source_sha = 'd'.repeat(40);
    if (damage === 'empty') f.data.components = {};
    if (damage === 'symlink') {
      const file = path.join(f.root, f.data.components.worker.path);
      await fs.unlink(file); await fs.symlink(path.join(f.root, f.data.components.web.path), file);
    }
    await f.save(); await assert.rejects(upload(f.args)); assert.equal(f.calls.length, 0, damage);
  }
});

test('invalid producer and partial service failure never return a complete output map', async t => {
  const f = await fixture(t);
  for (const changed of [{sourceSha: 'demo'}, {runId: '0'}, {runAttempt: '../2'}]) {
    await assert.rejects(upload({...f.args, ...changed})); assert.equal(f.calls.length, 0);
  }
  f.client.uploadArtifact = async () => {throw new Error('transport unavailable');};
  await assert.rejects(upload(f.args), /transport unavailable/);
  f.client.uploadArtifact = async () => ({id: 0, digest: 'b'.repeat(64), size: 5});
  await assert.rejects(upload(f.args), /Incomplete upload response/);
});
