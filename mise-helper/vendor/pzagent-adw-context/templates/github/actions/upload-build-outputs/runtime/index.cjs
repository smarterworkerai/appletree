/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ 2613:
/***/ ((module) => {

module.exports = require("assert");

/***/ }),

/***/ 181:
/***/ ((module) => {

module.exports = require("buffer");

/***/ }),

/***/ 5317:
/***/ ((module) => {

module.exports = require("child_process");

/***/ }),

/***/ 9140:
/***/ ((module) => {

module.exports = require("constants");

/***/ }),

/***/ 6982:
/***/ ((module) => {

module.exports = require("crypto");

/***/ }),

/***/ 4434:
/***/ ((module) => {

module.exports = require("events");

/***/ }),

/***/ 9896:
/***/ ((module) => {

module.exports = require("fs");

/***/ }),

/***/ 1943:
/***/ ((module) => {

module.exports = require("fs/promises");

/***/ }),

/***/ 8611:
/***/ ((module) => {

module.exports = require("http");

/***/ }),

/***/ 5692:
/***/ ((module) => {

module.exports = require("https");

/***/ }),

/***/ 9278:
/***/ ((module) => {

module.exports = require("net");

/***/ }),

/***/ 4589:
/***/ ((module) => {

module.exports = require("node:assert");

/***/ }),

/***/ 6698:
/***/ ((module) => {

module.exports = require("node:async_hooks");

/***/ }),

/***/ 4573:
/***/ ((module) => {

module.exports = require("node:buffer");

/***/ }),

/***/ 7540:
/***/ ((module) => {

module.exports = require("node:console");

/***/ }),

/***/ 7598:
/***/ ((module) => {

module.exports = require("node:crypto");

/***/ }),

/***/ 3053:
/***/ ((module) => {

module.exports = require("node:diagnostics_channel");

/***/ }),

/***/ 610:
/***/ ((module) => {

module.exports = require("node:dns");

/***/ }),

/***/ 8474:
/***/ ((module) => {

module.exports = require("node:events");

/***/ }),

/***/ 3024:
/***/ ((module) => {

module.exports = require("node:fs");

/***/ }),

/***/ 1455:
/***/ ((module) => {

module.exports = require("node:fs/promises");

/***/ }),

/***/ 7067:
/***/ ((module) => {

module.exports = require("node:http");

/***/ }),

/***/ 2467:
/***/ ((module) => {

module.exports = require("node:http2");

/***/ }),

/***/ 4708:
/***/ ((module) => {

module.exports = require("node:https");

/***/ }),

/***/ 7030:
/***/ ((module) => {

module.exports = require("node:net");

/***/ }),

/***/ 8161:
/***/ ((module) => {

module.exports = require("node:os");

/***/ }),

/***/ 6760:
/***/ ((module) => {

module.exports = require("node:path");

/***/ }),

/***/ 643:
/***/ ((module) => {

module.exports = require("node:perf_hooks");

/***/ }),

/***/ 1708:
/***/ ((module) => {

module.exports = require("node:process");

/***/ }),

/***/ 1792:
/***/ ((module) => {

module.exports = require("node:querystring");

/***/ }),

/***/ 7075:
/***/ ((module) => {

module.exports = require("node:stream");

/***/ }),

/***/ 6193:
/***/ ((module) => {

module.exports = require("node:string_decoder");

/***/ }),

/***/ 1692:
/***/ ((module) => {

module.exports = require("node:tls");

/***/ }),

/***/ 3136:
/***/ ((module) => {

module.exports = require("node:url");

/***/ }),

/***/ 7975:
/***/ ((module) => {

module.exports = require("node:util");

/***/ }),

/***/ 3429:
/***/ ((module) => {

module.exports = require("node:util/types");

/***/ }),

/***/ 5919:
/***/ ((module) => {

module.exports = require("node:worker_threads");

/***/ }),

/***/ 8522:
/***/ ((module) => {

module.exports = require("node:zlib");

/***/ }),

/***/ 857:
/***/ ((module) => {

module.exports = require("os");

/***/ }),

/***/ 6928:
/***/ ((module) => {

module.exports = require("path");

/***/ }),

/***/ 2203:
/***/ ((module) => {

module.exports = require("stream");

/***/ }),

/***/ 3193:
/***/ ((module) => {

module.exports = require("string_decoder");

/***/ }),

/***/ 3557:
/***/ ((module) => {

module.exports = require("timers");

/***/ }),

/***/ 4756:
/***/ ((module) => {

module.exports = require("tls");

/***/ }),

/***/ 2018:
/***/ ((module) => {

module.exports = require("tty");

/***/ }),

/***/ 7016:
/***/ ((module) => {

module.exports = require("url");

/***/ }),

/***/ 9023:
/***/ ((module) => {

module.exports = require("util");

/***/ }),

/***/ 725:
/***/ ((module) => {

module.exports = require("zlib");

/***/ }),

/***/ 2882:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


const fs = __nccwpck_require__(1455);
const {createReadStream} = __nccwpck_require__(3024);
const {createHash} = __nccwpck_require__(7598);
const path = __nccwpck_require__(6760);
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


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			id: moduleId,
/******/ 			loaded: false,
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId].call(module.exports, module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__nccwpck_require__.m = __webpack_modules__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/create fake namespace object */
/******/ 	(() => {
/******/ 		var getProto = Object.getPrototypeOf ? (obj) => (Object.getPrototypeOf(obj)) : (obj) => (obj.__proto__);
/******/ 		var leafPrototypes;
/******/ 		// create a fake namespace object
/******/ 		// mode & 1: value is a module id, require it
/******/ 		// mode & 2: merge all properties of value into the ns
/******/ 		// mode & 4: return value when already ns object
/******/ 		// mode & 16: return value when it's Promise-like
/******/ 		// mode & 8|1: behave like require
/******/ 		__nccwpck_require__.t = function(value, mode) {
/******/ 			if(mode & 1) value = this(value);
/******/ 			if(mode & 8) return value;
/******/ 			if(typeof value === 'object' && value) {
/******/ 				if((mode & 4) && value.__esModule) return value;
/******/ 				if((mode & 16) && typeof value.then === 'function') return value;
/******/ 			}
/******/ 			var ns = Object.create(null);
/******/ 			__nccwpck_require__.r(ns);
/******/ 			var def = {};
/******/ 			leafPrototypes = leafPrototypes || [null, getProto({}), getProto([]), getProto(getProto)];
/******/ 			for(var current = mode & 2 && value; typeof current == 'object' && !~leafPrototypes.indexOf(current); current = getProto(current)) {
/******/ 				Object.getOwnPropertyNames(current).forEach((key) => (def[key] = () => (value[key])));
/******/ 			}
/******/ 			def['default'] = () => (value);
/******/ 			__nccwpck_require__.d(ns, def);
/******/ 			return ns;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__nccwpck_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__nccwpck_require__.o(definition, key) && !__nccwpck_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/ensure chunk */
/******/ 	(() => {
/******/ 		__nccwpck_require__.f = {};
/******/ 		// This file contains only the entry chunk.
/******/ 		// The chunk loading function for additional chunks
/******/ 		__nccwpck_require__.e = (chunkId) => {
/******/ 			return Promise.all(Object.keys(__nccwpck_require__.f).reduce((promises, key) => {
/******/ 				__nccwpck_require__.f[key](chunkId, promises);
/******/ 				return promises;
/******/ 			}, []));
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/get javascript chunk filename */
/******/ 	(() => {
/******/ 		// This function allow to reference async chunks
/******/ 		__nccwpck_require__.u = (chunkId) => {
/******/ 			// return url for filenames based on template
/******/ 			return "" + chunkId + ".index.cjs.js";
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__nccwpck_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__nccwpck_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/node module decorator */
/******/ 	(() => {
/******/ 		__nccwpck_require__.nmd = (module) => {
/******/ 			module.paths = [];
/******/ 			if (!module.children) module.children = [];
/******/ 			return module;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/******/ 	/* webpack/runtime/require chunk loading */
/******/ 	(() => {
/******/ 		// no baseURI
/******/ 		
/******/ 		// object to store loaded chunks
/******/ 		// "1" means "loaded", otherwise not loaded yet
/******/ 		var installedChunks = {
/******/ 			792: 1
/******/ 		};
/******/ 		
/******/ 		// no on chunks loaded
/******/ 		
/******/ 		var installChunk = (chunk) => {
/******/ 			var moreModules = chunk.modules, chunkIds = chunk.ids, runtime = chunk.runtime;
/******/ 			for(var moduleId in moreModules) {
/******/ 				if(__nccwpck_require__.o(moreModules, moduleId)) {
/******/ 					__nccwpck_require__.m[moduleId] = moreModules[moduleId];
/******/ 				}
/******/ 			}
/******/ 			if(runtime) runtime(__nccwpck_require__);
/******/ 			for(var i = 0; i < chunkIds.length; i++)
/******/ 				installedChunks[chunkIds[i]] = 1;
/******/ 		
/******/ 		};
/******/ 		
/******/ 		// require() chunk loading for javascript
/******/ 		__nccwpck_require__.f.require = (chunkId, promises) => {
/******/ 			// "1" is the signal for "already loaded"
/******/ 			if(!installedChunks[chunkId]) {
/******/ 				if(true) { // all chunks have JS
/******/ 					installChunk(require("./" + __nccwpck_require__.u(chunkId)));
/******/ 				} else installedChunks[chunkId] = 1;
/******/ 			}
/******/ 		};
/******/ 		
/******/ 		// no external install chunk
/******/ 		
/******/ 		// no HMR
/******/ 		
/******/ 		// no HMR manifest
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};

const {upload} = __nccwpck_require__(2882);
async function main() {
  const core = await __nccwpck_require__.e(/* import() */ 659).then(__nccwpck_require__.bind(__nccwpck_require__, 1659));
  try {
    const {DefaultArtifactClient} = await Promise.all(/* import() */[__nccwpck_require__.e(659), __nccwpck_require__.e(445)]).then(__nccwpck_require__.bind(__nccwpck_require__, 3445));
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

module.exports = __webpack_exports__;
/******/ })()
;