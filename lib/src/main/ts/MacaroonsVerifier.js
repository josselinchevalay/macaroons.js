"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const BufferTools_1 = require("./BufferTools");
const CaveatPacketType_1 = require("./CaveatPacketType");
const CryptoTools_1 = require("./CryptoTools");
const MacaroonsConstants_1 = require("./MacaroonsConstants");
class MacaroonsVerifier {
    constructor(macaroon) {
        this.predicates = [];
        this.boundMacaroons = [];
        this.generalCaveatVerifiers = [];
        this.macaroon = macaroon;
    }
    static containsElement(elements, anElement) {
        if (elements !== null && elements.filter(e => e === anElement).length > 0) {
            return true;
        }
        return false;
    }
    assertIsValid(secret) {
        const secretBuffer = (secret instanceof Buffer) ? secret : CryptoTools_1.default.generate_derived_key(secret);
        const result = this.isValid_verify_raw(this.macaroon, secretBuffer);
        if (result.fail) {
            const msg = result.failMessage !== undefined ? result.failMessage : "This macaroon isn't valid.";
            throw new Error(msg);
        }
    }
    isValid(secret) {
        const secretBuffer = CryptoTools_1.default.generate_derived_key(secret.toString());
        return !this.isValid_verify_raw(this.macaroon, secretBuffer).fail;
    }
    satisfyExact(caveat) {
        if (caveat) {
            this.predicates.push(caveat);
        }
        return this;
    }
    satisfy3rdParty(preparedMacaroon) {
        if (preparedMacaroon) {
            this.boundMacaroons.push(preparedMacaroon);
        }
        return this;
    }
    satisfyGeneral(generalVerifier) {
        if (generalVerifier) {
            this.generalCaveatVerifiers.push(generalVerifier);
        }
        return this;
    }
    isValid_verify_raw(M, secret) {
        let vresult = this.macaroon_verify_inner(M, secret);
        if (!vresult.fail) {
            vresult.fail = !BufferTools_1.default.equals(vresult.csig, this.macaroon.signatureBuffer);
            if (vresult.fail) {
                vresult = new VerificationResult("Verification failed. Signature doesn't match. Maybe the key was wrong OR some caveats aren't satisfied.");
            }
        }
        return vresult;
    }
    macaroon_verify_inner(M, key) {
        let csig = CryptoTools_1.default.macaroon_hmac(key, M.identifier);
        if (M.caveatPackets !== undefined) {
            const caveatPackets = M.caveatPackets;
            for (let i = 0; i < caveatPackets.length; i++) {
                const caveat = caveatPackets[i];
                if (caveat === undefined) {
                    continue;
                }
                if (caveat.type === CaveatPacketType_1.CaveatPacketType.cl) {
                    continue;
                }
                if (!(caveat.type === CaveatPacketType_1.CaveatPacketType.cid && caveatPackets[Math.min(i + 1, caveatPackets.length - 1)].type === CaveatPacketType_1.CaveatPacketType.vid)) {
                    if (MacaroonsVerifier.containsElement(this.predicates, caveat.getValueAsText()) || this.verifiesGeneral(caveat.getValueAsText())) {
                        csig = CryptoTools_1.default.macaroon_hmac(csig, caveat.rawValue);
                    }
                }
                else {
                    i++;
                    const caveatVid = caveatPackets[i];
                    const boundMacaroon = this.findBoundMacaroon(caveat.getValueAsText());
                    if (boundMacaroon === undefined) {
                        const msg = "Couldn't verify 3rd party macaroon, because no discharged macaroon was provided to the verifier.";
                        return new VerificationResult(msg);
                    }
                    if (!this.macaroon_verify_inner_3rd(boundMacaroon, caveatVid, csig)) {
                        const msg = `Couldn't verify 3rd party macaroon, identifier= ${boundMacaroon.identifier}`;
                        return new VerificationResult(msg);
                    }
                    const data = caveat.rawValue;
                    const vdata = caveatVid.rawValue;
                    csig = CryptoTools_1.default.macaroon_hash2(csig, vdata, data);
                }
            }
        }
        return new VerificationResult(csig);
    }
    macaroon_verify_inner_3rd(M, C, sig) {
        if (!M) {
            return false;
        }
        let encPlaintext = new Buffer(MacaroonsConstants_1.default.MACAROON_SECRET_TEXT_ZERO_BYTES + MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        const encCipherText = new Buffer(MacaroonsConstants_1.default.MACAROON_HASH_BYTES + MacaroonsConstants_1.default.SECRET_BOX_OVERHEAD);
        encPlaintext.fill(0);
        encCipherText.fill(0);
        const vidData = C.rawValue;
        const encNonce = new Buffer(MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES);
        vidData.copy(encNonce, 0, 0, encNonce.length);
        vidData.copy(encCipherText, 0, MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES, MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES + vidData.length - MacaroonsConstants_1.default.MACAROON_SECRET_NONCE_BYTES);
        try {
            encPlaintext = CryptoTools_1.default.macaroon_secretbox_open(sig, encNonce, encCipherText);
        }
        catch (error) {
            if (/Cipher bytes fail verification/.test(error.message)) {
                return false;
            }
            else {
                throw new Error(`Error while deciphering 3rd party caveat, msg=${error}`);
            }
        }
        const key = new Buffer(MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        key.fill(0);
        encPlaintext.copy(key, 0, 0, MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        const vresult = this.macaroon_verify_inner(M, key);
        const data = this.macaroon.signatureBuffer;
        const csig = CryptoTools_1.default.macaroon_bind(data, vresult.csig);
        return BufferTools_1.default.equals(csig, M.signatureBuffer);
    }
    findBoundMacaroon(identifier) {
        for (let i = 0; i < this.boundMacaroons.length; i++) {
            const boundMacaroon = this.boundMacaroons[i];
            if (identifier === boundMacaroon.identifier) {
                return boundMacaroon;
            }
        }
        return undefined;
    }
    verifiesGeneral(caveat) {
        let found = false;
        for (var i = 0; i < this.generalCaveatVerifiers.length; i++) {
            const verifier = this.generalCaveatVerifiers[i];
            found = found || verifier(caveat);
        }
        return found;
    }
}
exports.default = MacaroonsVerifier;
class VerificationResult {
    constructor(arg) {
        this.csig = null;
        this.fail = false;
        this.failMessage = null;
        if (typeof arg === 'string') {
            this.failMessage = arg;
            this.fail = true;
        }
        else if (typeof arg === 'object') {
            this.csig = arg;
        }
    }
}
//# sourceMappingURL=MacaroonsVerifier.js.map