let wasm;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_2.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); }
let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function main() {
    wasm.main();
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_2.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}
/**
 * @param {any} message
 * @returns {any}
 */
function handle_message$1(message) {
    const ret = wasm.handle_message(message);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_buffer_609cc3eee51ed158 = function(arg0) {
        const ret = arg0.buffer;
        return ret;
    };
    imports.wbg.__wbg_call_672a4d21634d4a24 = function() { return handleError(function (arg0, arg1) {
        const ret = arg0.call(arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_7cccdd69e0791ae2 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = arg0.call(arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_crypto_574e78ad8b13b65f = function(arg0) {
        const ret = arg0.crypto;
        return ret;
    };
    imports.wbg.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
        let deferred0_0;
        let deferred0_1;
        try {
            deferred0_0 = arg0;
            deferred0_1 = arg1;
            console.error(getStringFromWasm0(arg0, arg1));
        } finally {
            wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
        }
    };
    imports.wbg.__wbg_getRandomValues_b8f5dbd5f3995a9e = function() { return handleError(function (arg0, arg1) {
        arg0.getRandomValues(arg1);
    }, arguments) };
    imports.wbg.__wbg_log_c222819a41e063d3 = function(arg0) {
        console.log(arg0);
    };
    imports.wbg.__wbg_msCrypto_a61aeb35a24c1329 = function(arg0) {
        const ret = arg0.msCrypto;
        return ret;
    };
    imports.wbg.__wbg_new_8a6f238a6ece86ea = function() {
        const ret = new Error();
        return ret;
    };
    imports.wbg.__wbg_new_a12002a7f91c75be = function(arg0) {
        const ret = new Uint8Array(arg0);
        return ret;
    };
    imports.wbg.__wbg_newnoargs_105ed471475aaf50 = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_newwithbyteoffsetandlength_d97e637ebe145a9a = function(arg0, arg1, arg2) {
        const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_newwithlength_a381634e90c276d4 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_node_905d3e251edff8a2 = function(arg0) {
        const ret = arg0.node;
        return ret;
    };
    imports.wbg.__wbg_now_807e54c39636c349 = function() {
        const ret = Date.now();
        return ret;
    };
    imports.wbg.__wbg_parse_def2e24ef1252aff = function() { return handleError(function (arg0, arg1) {
        const ret = JSON.parse(getStringFromWasm0(arg0, arg1));
        return ret;
    }, arguments) };
    imports.wbg.__wbg_process_dc0fbacc7c1c06f7 = function(arg0) {
        const ret = arg0.process;
        return ret;
    };
    imports.wbg.__wbg_randomFillSync_ac0988aba3254290 = function() { return handleError(function (arg0, arg1) {
        arg0.randomFillSync(arg1);
    }, arguments) };
    imports.wbg.__wbg_require_60cc747a6bc5215a = function() { return handleError(function () {
        const ret = module.require;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_set_65595bdd868b3009 = function(arg0, arg1, arg2) {
        arg0.set(arg1, arg2 >>> 0);
    };
    imports.wbg.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
        const ret = arg1.stack;
        const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_88a902d13a557d07 = function() {
        const ret = typeof global === 'undefined' ? null : global;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0 = function() {
        const ret = typeof globalThis === 'undefined' ? null : globalThis;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_SELF_37c5d418e4bf5819 = function() {
        const ret = typeof self === 'undefined' ? null : self;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_WINDOW_5de37043a91a9c40 = function() {
        const ret = typeof window === 'undefined' ? null : window;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_stringify_f7ed6987935b4a24 = function() { return handleError(function (arg0) {
        const ret = JSON.stringify(arg0);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_subarray_aa9065fa9dc5df96 = function(arg0, arg1, arg2) {
        const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_versions_c01dfd4722a88165 = function(arg0) {
        const ret = arg0.versions;
        return ret;
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_export_2;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
    };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(arg0) === 'function';
        return ret;
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = arg0;
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(arg0) === 'string';
        return ret;
    };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = arg0 === undefined;
        return ret;
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return ret;
    };
    imports.wbg.__wbindgen_string_get = function(arg0, arg1) {
        const obj = arg1;
        const ret = typeof(obj) === 'string' ? obj : undefined;
        var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };

    return imports;
}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module);
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead');
        }
    }

    const imports = __wbg_get_imports();

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path);
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead');
        }
    }

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('vrf_service_worker_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

var vrfWasmModule = /*#__PURE__*/Object.freeze({
    __proto__: null,
    default: __wbg_init,
    handle_message: handle_message$1,
    initSync: initSync,
    main: main
});

/**
 * VRF WASM Web Worker
 *
 * This Web Worker loads the VRF WASM module and provides VRF keypair management.
 */
// Import VRF WASM module directly (same pattern as onetimePasskeySigner.worker.ts)
// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('./vrf_service_worker_bg.wasm', import.meta.url);
// === VRF WASM MODULE FUNCTIONS ===
const { handle_message } = vrfWasmModule;
// === GLOBAL STATE ===
/** VRF WASM module instance */
let wasmModule = null;
/** WASM initialization state */
let wasmInitialized = false;
// === WASM MODULE MANAGEMENT ===
/**
 * Initialize WASM module for VRF operations with timeout protection
 */
async function initializeWasmModule() {
    if (wasmInitialized) {
        console.log('🔧 VRF WASM Web Worker: Already initialized, skipping...');
        return;
    }
    console.log('🔧 VRF WASM Web Worker: Starting WASM initialization...');
    try {
        // Add timeout protection for WASM initialization
        const initPromise = (async () => {
            console.log('📥 VRF WASM Web Worker: WASM URL:', wasmUrl.href);
            console.log('📥 VRF WASM Web Worker: Available functions:', Object.keys(vrfWasmModule));
            // Initialize WASM module
            console.log('🚀 VRF WASM Web Worker: Calling init()...');
            await __wbg_init();
            console.log('✅ VRF WASM Web Worker: init() completed successfully');
            // Test that the handle_message function is available
            if (typeof handle_message !== 'function') {
                throw new Error('handle_message function not available after WASM initialization');
            }
            console.log('✅ VRF WASM Web Worker: handle_message function verified');
        })();
        // Race initialization against timeout
        await Promise.race([
            initPromise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('WASM initialization timeout after 20 seconds')), 20000))
        ]);
        // Create wrapper with the proper handle_message function
        const wasmInstance = {
            handle_message: (message) => {
                try {
                    console.log('VRF WASM: Processing message:', message.type);
                    // Call the actual WASM function
                    const result = handle_message(message);
                    return result;
                }
                catch (error) {
                    console.error('VRF WASM: Error processing message:', error);
                    return {
                        id: message.id,
                        success: false,
                        error: error.message || 'WASM processing error'
                    };
                }
            }
        };
        wasmModule = wasmInstance;
        wasmInitialized = true;
        console.log('✅ VRF WASM Web Worker: WASM module loaded and initialized successfully');
        // Quick test of the WASM functionality
        try {
            const testResponse = wasmModule.handle_message({
                type: 'PING',
                id: 'init-test',
                data: {}
            });
            console.log('✅ VRF WASM Web Worker: Initialization test successful:', testResponse.success);
        }
        catch (testError) {
            console.warn('⚠️ VRF WASM Web Worker: Initialization test failed, but continuing:', testError.message);
        }
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown WASM initialization error';
        console.error('❌ VRF WASM Web Worker: Failed to load WASM module:', errorMessage);
        console.error('❌ VRF WASM Web Worker: Error details:', error);
        wasmInitialized = false;
        // Create a fallback module that returns errors
        wasmModule = {
            handle_message: (message) => {
                return {
                    id: message.id,
                    success: false,
                    error: `WASM initialization failed: ${errorMessage}`
                };
            }
        };
        // Re-throw the error to be handled by the caller
        throw new Error(`VRF WASM initialization failed: ${errorMessage}`);
    }
}
// === MESSAGE HANDLING ===
/**
 * Create standardized error response
 */
function createErrorResponse(messageId, error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error in Web Worker';
    return {
        id: messageId,
        success: false,
        error: errorMessage
    };
}
// Web Worker message handling
self.onmessage = async (event) => {
    const data = event.data;
    try {
        console.log('📨 VRF WASM Web Worker: Received message:', data.type);
        // Handle PING messages immediately for connectivity testing
        if (data.type === 'PING') {
            console.log('🏓 VRF WASM Web Worker: Responding to PING');
            const pingResponse = {
                id: data.id,
                success: true,
                data: {
                    status: 'alive',
                    wasmInitialized: wasmInitialized,
                    timestamp: Date.now()
                }
            };
            self.postMessage(pingResponse);
            return;
        }
        // For other messages, ensure WASM is initialized
        if (!wasmInitialized) {
            console.log('🔧 VRF WASM Web Worker: WASM not initialized, initializing now...');
            await initializeWasmModule();
        }
        if (!wasmInitialized || !wasmModule) {
            throw new Error('WASM module not initialized after initialization attempt');
        }
        console.log('📨 VRF WASM Web Worker: Processing message with WASM module');
        // Delegate to WASM module
        if (!wasmModule) {
            throw new Error('WASM module is null after initialization');
        }
        const response = wasmModule.handle_message(data);
        // Send response back to main thread
        self.postMessage(response);
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown message handling error';
        console.error('❌ VRF WASM Web Worker: Message handling error:', errorMessage);
        // Send error response
        const errorResponse = createErrorResponse(data?.id, error);
        self.postMessage(errorResponse);
    }
};
// === ERROR HANDLING ===
// Global error handling
self.onerror = (error) => {
    console.error('❌ VRF WASM Web Worker: Global error:', error);
};
// Unhandled promise rejection handling
self.onunhandledrejection = (event) => {
    console.error('❌ VRF WASM Web Worker: Unhandled promise rejection:', event.reason);
    event.preventDefault();
};
// === INITIALIZATION ===
console.log('🔧 VRF WASM Web Worker: Script loaded');
// Initialize WASM on worker startup
initializeWasmModule().catch(error => {
    console.error('❌ VRF WASM Web Worker: Startup initialization failed:', error);
    // Continue anyway - errors will be returned to clients
});
//# sourceMappingURL=vrf-service-worker.js.map
