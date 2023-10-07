import axios from 'axios'

let isWasmLoaded = false

window.Module = {}
window.Module.onRuntimeInitialized = function () {
    isWasmLoaded = true
}

const waitGMLoad = async () => {
    return new Promise((resolve, reject) => {
        if (isWasmLoaded) {
            resolve()
        } else {
            window.Module.onRuntimeInitialized = function () {
                isWasmLoaded = true
                resolve()
            }
        }
    })
}

// 加载 gmssl-wasm.js
const wasmResp = await axios.get(`./gmssl-wasm.js?t=${new Date().getTime()}`)
const script = document.createElement('script')
script.type = 'text/javascript'
script.text = wasmResp.data
document.body.appendChild(script)

const get_uint8_wasm_ptr_from_buffer_array = (arr) => {
    let arr_ptr = window.Module._malloc_buf(arr.length)
    let arr_buffer = new Uint8Array(Module.HEAPU8.buffer, arr_ptr, arr.length)

    for (let i = 0; i < arr.length; i++) {
        arr_buffer[i] = arr[i]
    }
    return {
        ptr: arr_ptr,
        len: arr_buffer.length
    }
}

const get_uint8_wasm_ptr_from_str = (str) => {
    let encoder = new TextEncoder()
    let str_array = encoder.encode(str)
    return get_uint8_wasm_ptr_from_buffer_array(str_array)
}

const get_uint8_wasm_ptr_from_hex_str = (str) => {
    let hex_buffer_array = new Uint8Array(str.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16)
    }))
    return get_uint8_wasm_ptr_from_buffer_array(hex_buffer_array)
}

const sm3 = (plain) => {
    let {ptr: plain_ptr, len: plain_len} = get_uint8_wasm_ptr_from_str(plain)

    let ptr = window.Module._iasp_sm3(plain_ptr, plain_len)
    let ciphertext = window.Module.UTF8ToString(ptr)

    window.Module._free_buf(plain_ptr)
    window.Module._free_buf(ptr)
    return ciphertext
}

const sm4_encrypt = (key, iv, plain) => {
    let {ptr: key_ptr, len: key_len} = get_uint8_wasm_ptr_from_hex_str(key)
    let {ptr: iv_ptr, len: iv_len} = get_uint8_wasm_ptr_from_hex_str(iv)
    let {ptr: plain_ptr, len: plain_len} = get_uint8_wasm_ptr_from_str(plain)

    let ptr = window.Module._iasp_sm4_encrypt(key_ptr, key_len, iv_ptr, iv_len, plain_ptr, plain_len)
    let ciphertext = window.Module.UTF8ToString(ptr)

    window.Module._free_buf(key_ptr)
    window.Module._free_buf(iv_ptr)
    window.Module._free_buf(plain_ptr)
    window.Module._free_buf(ptr)
    return ciphertext
}

const sm4_decrypt = (key, iv, hexCiphertext) => {
    let {ptr: key_ptr, len: key_len} = get_uint8_wasm_ptr_from_hex_str(key)
    let {ptr: iv_ptr, len: iv_len} = get_uint8_wasm_ptr_from_hex_str(iv)
    let {ptr: cipher_ptr, len: cipher_len} = get_uint8_wasm_ptr_from_hex_str(hexCiphertext)

    let ptr = window.Module._iasp_sm4_decrypt(key_ptr, key_len, iv_ptr, iv_len, cipher_ptr, cipher_len)
    let plaintext = window.Module.UTF8ToString(ptr)

    window.Module._free_buf(key_ptr)
    window.Module._free_buf(iv_ptr)
    window.Module._free_buf(cipher_ptr)
    window.Module._free_buf(ptr)
    return plaintext
}

const sm4_encrypt_simple = (key, plain) => {
    return sm4_encrypt(key, '6A476BBB34ED0FE588ADB2D6FCDEF369', plain)
}

const sm4_decrypt_simple = (key, hexCiphertext) => {
    return sm4_decrypt(key, '6A476BBB34ED0FE588ADB2D6FCDEF369', hexCiphertext)
}

const sm2_gen_key = () => {
    let pri_buff_len = 1000
    let pri_buff_ptr = window.Module._malloc_buf(pri_buff_len)
    let pub_buff_len = 1000
    let pub_buff_ptr = window.Module._malloc_buf(pub_buff_len)

    window.Module._iasp_sm2_gen(pri_buff_ptr, pri_buff_len, pub_buff_ptr, pub_buff_len)

    let pri_arr_buffer = new Uint8Array(Module.HEAPU8.buffer, pri_buff_ptr, pri_buff_len)
    let pub_arr_buffer = new Uint8Array(Module.HEAPU8.buffer, pub_buff_ptr, pub_buff_len)

    let sm2_key = ''
    let pub_key = ''

    for (let i = 0; i < pri_buff_len; i++) {
        sm2_key += String.fromCharCode(pri_arr_buffer[i])
    }
    for (let i = 0; i < pub_buff_len; i++) {
        pub_key += String.fromCharCode(pub_arr_buffer[i])
    }
    window.Module._free_buf(pri_buff_ptr)
    window.Module._free_buf(pub_buff_ptr)

    return {
        pri: sm2_key,
        pub: pub_key
    }
}

const sm2_encrypt = (pub, plain) => {
    let {ptr: pub_ptr, len: pub_len} = get_uint8_wasm_ptr_from_str(pub)
    let {ptr: plain_ptr, len: plain_len} = get_uint8_wasm_ptr_from_str(plain)

    let ptr = window.Module._iasp_sm2_encrypt(pub_ptr, pub_len, plain_ptr, plain_len)
    let ciphertext = window.Module.UTF8ToString(ptr)

    window.Module._free_buf(pub_ptr)
    window.Module._free_buf(plain_ptr)
    window.Module._free_buf(ptr)
    return ciphertext
}

const sm2_decrypt = (pri, cipher) => {
    let {ptr: pri_ptr, len: pri_len} = get_uint8_wasm_ptr_from_str(pri)
    let {ptr: cipher_ptr, len: cipher_len} = get_uint8_wasm_ptr_from_hex_str(cipher)

    let ptr = window.Module._iasp_sm2_decrypt(pri_ptr, pri_len, cipher_ptr, cipher_len)
    let plaintext = window.Module.UTF8ToString(ptr)

    window.Module._free_buf(pri_ptr)
    window.Module._free_buf(cipher_ptr)
    window.Module._free_buf(ptr)
    return plaintext
}

const sm2_sign = (pri, digest) => {
    let {ptr: pri_ptr, len: pri_len} = get_uint8_wasm_ptr_from_str(pri)
    let {ptr: digest_ptr, len: digest_len} = get_uint8_wasm_ptr_from_str(digest)

    let ptr = window.Module._iasp_sm2_sign(pri_ptr, pri_len, digest_ptr, digest_len)
    let signature = window.Module.UTF8ToString(ptr)

    window.Module._free_buf(pri_ptr)
    window.Module._free_buf(digest_ptr)
    window.Module._free_buf(ptr)
    return signature
}

const sm2_verify = (pub, digest, signature) => {
    let {ptr: pub_ptr, len: pub_len} = get_uint8_wasm_ptr_from_str(pub)
    let {ptr: digest_ptr, len: digest_len} = get_uint8_wasm_ptr_from_str(digest)
    let {ptr: signature_ptr, len: signature_len} = get_uint8_wasm_ptr_from_hex_str(signature)

    let ret = window.Module._iasp_sm2_verify(pub_ptr, pub_len, digest_ptr, digest_len, signature_ptr, signature_len)

    window.Module._free_buf(pub_ptr)
    window.Module._free_buf(digest_ptr)
    window.Module._free_buf(signature_ptr)
    return ret === 0
}

export {
    waitGMLoad,
    sm2_gen_key,
    sm2_encrypt,
    sm2_decrypt,
    sm2_sign,
    sm2_verify,
    sm3,
    sm4_encrypt,
    sm4_decrypt,
    sm4_encrypt_simple,
    sm4_decrypt_simple
}