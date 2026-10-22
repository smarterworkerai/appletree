# Declared build component upload

This Node24 action uploads one native GitHub artifact per declared build
component. It uses pinned `@actions/artifact` 6.2.0, the official client also
used by `actions/upload-artifact` v7. It contains no project language, component
name, compilation command or deployment credential requirement.

The project full-quality hook emits `upload-manifest.json` with schema version
`1.0.0`, the exact `source_sha`, and a `components` object. Each component has
`path` (`COMPONENT/build-output.tar.gz`), `sha256` and `size`. All files are
checked before any upload. The action creates names containing source SHA, run
ID, attempt and component; the source input comes from the CI umbrella.
Archives are retained for seven days, wrapped in native ZIP with compression
level zero. No artifact is overwritten. The output is a component-to-artifact
identity/checksum mapping and a comma-separated native ID list.

The installed workflow keeps upload optional after successful full quality.
Publication independently verifies the authorized run/attempt/job and server
artifact digest before importing a selected component. Upload output alone is
not release authorization. If upload fails partway, publication can rebuild;
no complete output map is returned for the failed action.

The checked-in `runtime/` contains the bundled action and dependency licenses;
it requires no package install in CI. `package-lock.json` pins the rebuild.
A consumer can build the action in a temporary directory and then restage the
development vendor candidate. The shared package can run
`npm ci --ignore-scripts` and `npm run build` in an isolated copy. Node24 is the execution target. `node --test upload.test.cjs`
checks selection, integrity, transport options and failure handling without a
network service; the act lab separately exercises real native artifact upload.

Primary API reference:
[GitHub artifact toolkit](https://github.com/actions/toolkit/tree/main/packages/artifact).
