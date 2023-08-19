/* tslint:disable */
/* eslint-disable */
/**
*/
export class Key {
  free(): void;
}
/**
*/
export class Keypair {
  free(): void;
}
/**
* A `NoiseSession` object is used to keep track of the states of both local
* and remote parties before, during, and after a handshake.
*
* It contains:
* - `hs`: Keeps track of the local party's state while a handshake is being
*   performed.
* - `h`:  Stores the handshake hash output after a successful handshake in a
*   Hash object. Is initialized as array of 0 bytes.
* - `cs1`: Keeps track of the local party's post-handshake state. Contains a
*   cryptographic key and a nonce.
* - `cs2`: Keeps track of the remote party's post-handshake state. Contains a
*   cryptographic key and a nonce.
* - `mc`:  Keeps track of the total number of incoming and outgoing messages,
*   including those sent during a handshake.
* - `i`: `bool` value that indicates whether this session corresponds to the
*   local or remote party.
* - `is_transport`: `bool` value that indicates whether a handshake has been
*   performed succesfully with a remote session and the session is in transport mode.
*/
export class NoiseSession {
  free(): void;
}
/**
*/
export class PrivateKey {
  free(): void;
}
/**
*/
export class Psk {
  free(): void;
}
/**
*/
export class PublicKey {
  free(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_noisesession_free: (a: number) => void;
  readonly __wbg_key_free: (a: number) => void;
  readonly __wbg_keypair_free: (a: number) => void;
  readonly __wbg_psk_free: (a: number) => void;
  readonly __wbg_privatekey_free: (a: number) => void;
  readonly __wbg_publickey_free: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
