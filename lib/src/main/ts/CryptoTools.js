"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const ecma_nacl_1 = require("ecma-nacl");
const MacaroonsConstants_1 = require("./MacaroonsConstants");
const ThirdPartyPacket_1 = require("./ThirdPartyPacket");
const toBuffer = require('typedarray-to-buffer');
class CryptoTools {
    static generate_derived_key(variableKey) {
        const MACAROONS_MAGIC_KEY = new Buffer("macaroons-key-generator", "utf-8");
        return CryptoTools.macaroon_hmac(MACAROONS_MAGIC_KEY, new Buffer(variableKey, MacaroonsConstants_1.default.IDENTIFIER_CHARSET));
    }
    static macaroon_hmac(key, message) {
        if (typeof message === undefined) {
            throw new Error("Missing second parameter 'message'.");
        }
        const mac = crypto_1.createHmac('sha256', key);
        if (typeof message === 'string') {
            mac.update(new Buffer(message, MacaroonsConstants_1.default.IDENTIFIER_CHARSET));
        }
        else {
            mac.update(message);
        }
        return mac.digest();
    }
    static macaroon_hash2(key, message1, message2) {
        const tmp = new Buffer(MacaroonsConstants_1.default.MACAROON_HASH_BYTES * 2);
        CryptoTools.macaroon_hmac(key, message1).copy(tmp, 0, 0, MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        CryptoTools.macaroon_hmac(key, message2).copy(tmp, MacaroonsConstants_1.default.MACAROON_HASH_BYTES, 0, MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        return CryptoTools.macaroon_hmac(key, tmp);
    }
    static macaroon_add_third_party_caveat_raw(oldSig, key, identifier) {
        const derivedKey = CryptoTools.generate_derived_key(key);
        const encNonce = new Buffer(MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES);
        encNonce.fill(0);
        const encPlaintext = new Buffer(MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        encPlaintext.fill(0);
        derivedKey.copy(encPlaintext, 0, 0, MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        const encCiphertext = CryptoTools.macaroon_secretbox(oldSig, encNonce, encPlaintext);
        const vid = new Buffer(MacaroonsConstants_1.default.VID_NONCE_KEY_SZ);
        vid.fill(0);
        encNonce.copy(vid, 0, 0, MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES);
        encCiphertext.copy(vid, MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES, 0, MacaroonsConstants_1.default.VID_NONCE_KEY_SZ - MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES);
        const newSig = CryptoTools.macaroon_hash2(oldSig, vid, new Buffer(identifier, MacaroonsConstants_1.default.IDENTIFIER_CHARSET));
        return new ThirdPartyPacket_1.default(newSig, vid);
    }
    static macaroon_bind(Msig, MPsig) {
        const key = new Buffer(MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        key.fill(0);
        return CryptoTools.macaroon_hash2(key, Msig, MPsig);
    }
    static macaroon_secretbox(key, nonce, plaintext) {
        const cipherBytes = ecma_nacl_1.secret_box.pack(new Uint8Array(plaintext), new Uint8Array(nonce), new Uint8Array(key));
        return toBuffer(cipherBytes);
    }
    static macaroon_secretbox_open(encKey, encNonce, ciphertext) {
        const plainBytes = ecma_nacl_1.secret_box.open(new Uint8Array(ciphertext), new Uint8Array(encNonce), new Uint8Array(encKey));
        return toBuffer(plainBytes);
    }
}
exports.default = CryptoTools;
//# sourceMappingURL=CryptoTools.js.map