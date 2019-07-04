
let wasm;

let cachedTextDecoder = new TextDecoder('utf-8');

let cachegetUint8Memory = null;
function getUint8Memory() {
    if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory;
}

function getStringFromWasm(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
}
/**
*/
export class Key {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_key_free(ptr);
    }
}
/**
*/
export class Keypair {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_keypair_free(ptr);
    }
}
/**
* A `NoiseSession` object is used to keep track of the states of both local
* and remote parties before, during, and after a handshake.
*
* It contains:
* - `hs`: Keeps track of the local party\'s state while a handshake is being
*   performed.
* - `h`:  Stores the handshake hash output after a successful handshake in a
*   Hash object. Is initialized as array of 0 bytes.
* - `cs1`: Keeps track of the local party\'s post-handshake state. Contains a
*   cryptographic key and a nonce.
* - `cs2`: Keeps track of the remote party\'s post-handshake state. Contains a
*   cryptographic key and a nonce.
* - `mc`:  Keeps track of the total number of incoming and outgoing messages,
*   including those sent during a handshake.
* - `i`: `bool` value that indicates whether this session corresponds to the
*   local or remote party.
* - `is_transport`: `bool` value that indicates whether a handshake has been
*   performed succesfully with a remote session and the session is in transport mode.
*/
export class NoiseSession {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_noisesession_free(ptr);
    }
}
/**
*/
export class PrivateKey {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_privatekey_free(ptr);
    }
}
/**
*/
export class Psk {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_psk_free(ptr);
    }
}
/**
*/
export class PublicKey {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_publickey_free(ptr);
    }
}

function init(module) {
    if (typeof module === 'undefined') {
        module = import.meta.url.replace(/\.js$/, '_bg.wasm');
    }
    let result;
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        let varg0 = getStringFromWasm(arg0, arg1);
        throw new Error(varg0);
    };

    if (module instanceof URL || typeof module === 'string' || module instanceof Request) {

        const response = fetch(module);
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            result = WebAssembly.instantiateStreaming(response, imports)
            .catch(e => {
                console.warn("`WebAssembly.instantiateStreaming` failed. Assuming this is because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);
                return response
                .then(r => r.arrayBuffer())
                .then(bytes => WebAssembly.instantiate(bytes, imports));
            });
        } else {
            result = response
            .then(r => r.arrayBuffer())
            .then(bytes => WebAssembly.instantiate(bytes, imports));
        }
    } else {

        result = WebAssembly.instantiate(module, imports)
        .then(result => {
            if (result instanceof WebAssembly.Instance) {
                return { instance: result, module };
            } else {
                return result;
            }
        });
    }
    return result.then(({instance, module}) => {
        wasm = instance.exports;
        init.__wbindgen_wasm_module = module;

        return wasm;
    });
}

export default init;

