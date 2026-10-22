'use strict';
const fs = require('node:fs/promises');
const {createReadStream} = require('node:fs');
const {createHash} = require('node:crypto');
const path = require('node:path');
const COMPONENT = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_BYTES = 2 * 1024 * 1024 * 1024;

async function sha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function upload({manifest, sourceSha, runId, runAttempt, client}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha) || !/^[1-9][0-9]*$/.test(runId) ||
      !/^[1-9][0-9]*$/.test(runAttempt)) throw new Error('Invalid producer identity');
  const manifestStat = await fs.lstat(manifest);
  if (!manifestStat.isFile() || manifestStat.size > 1024 * 1024) throw new Error('Invalid upload manifest');
  const data = JSON.parse(await fs.readFile(manifest, 'utf8'));
  if (data.schema_version !== '1.0.0' || data.source_sha !== sourceSha ||
      !data.components || Array.isArray(data.components) || typeof data.components !== 'object') {
    throw new Error('Invalid upload selection');
  }
  const entries = Object.entries(data.components);
  if (!entries.length || entries.length > 32) throw new Error('Invalid component count');
  const root = await fs.realpath(path.dirname(manifest));
  const selected = [];
  // Validate every input before beginning any upload. Payloads are the sealed
  // tar files emitted by quality, never arbitrary paths or cache directories.
  for (const [component, value] of entries) {
    if (!COMPONENT.test(component) || !value || value.path !== `${component}/build-output.tar.gz` ||
        !SHA256.test(value.sha256) || !Number.isSafeInteger(value.size) || value.size <= 0 || value.size > MAX_BYTES) {
      throw new Error('Invalid component descriptor');
    }
    const file = path.join(root, value.path);
    const metadata = await fs.lstat(file);
    if (!metadata.isFile() || await fs.realpath(file) !== file || metadata.size !== value.size ||
        await sha256(file) !== value.sha256) throw new Error('Component payload changed');
    selected.push({component, file, value});
  }
  const results = {};
  for (const {component, file, value} of selected) {
    const name = `adw-build-${sourceSha}-${runId}-${runAttempt}-${component}`;
    const result = await client.uploadArtifact(name, [file], path.dirname(file), {
      retentionDays: 7, compressionLevel: 0, skipArchive: false,
    });
    if (!Number.isSafeInteger(result.id) || result.id <= 0 || !SHA256.test(result.digest) ||
        !Number.isSafeInteger(result.size) || result.size <= 0 || result.size > MAX_BYTES) {
      throw new Error('Incomplete upload response');
    }
    results[component] = {name, id: result.id, digest: 'sha256:' + result.digest,
                          archive_sha256: value.sha256, archive_bytes: value.size};
  }
  return results;
}
module.exports = {upload};
