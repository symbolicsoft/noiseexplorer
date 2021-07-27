
const path = require('path').join(__dirname, 'noiseexplorer_ikpsk2_bg.wasm');
const bytes = require('fs').readFileSync(path);
let imports = {};
imports['./noiseexplorer_ikpsk2.js'] = require('./noiseexplorer_ikpsk2.js');

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
module.exports = wasmInstance.exports;
