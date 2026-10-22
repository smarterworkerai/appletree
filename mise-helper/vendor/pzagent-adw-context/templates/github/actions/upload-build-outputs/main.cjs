'use strict';
const {upload} = require('./upload.cjs');
async function main() {
  const core = await import('@actions/core');
  try {
    const {DefaultArtifactClient} = await import('@actions/artifact');
    const result = await upload({
      manifest: core.getInput('manifest', {required: true}),
      sourceSha: core.getInput('source-sha', {required: true}),
      runId: process.env.GITHUB_RUN_ID, runAttempt: process.env.GITHUB_RUN_ATTEMPT,
      client: new DefaultArtifactClient(),
    });
    core.setOutput('artifacts', JSON.stringify(result));
    core.setOutput('artifact-ids', Object.values(result).map(item => item.id).join(','));
  } catch {
    core.setFailed('Build component artifact upload failed; publication can rebuild through ADW');
  }
}
main();
