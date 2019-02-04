"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const CaveatPacket_1 = require("./CaveatPacket");
const CaveatPacketType_1 = require("./CaveatPacketType");
const CryptoTools_1 = require("./CryptoTools");
const Macaroon_1 = require("./Macaroon");
const MacaroonsConstants_1 = require("./MacaroonsConstants");
const MacaroonsDeSerializer_1 = require("./MacaroonsDeSerializer");
class MacaroonsBuilder {
    constructor(arg1, secretKey, identifier) {
        if (typeof arg1 === 'string') {
            if (typeof secretKey !== 'string' && !(secretKey instanceof Buffer)) {
                throw new Error("The secret key has to be a simple string or an instance of Buffer.");
            }
            this.macaroon = this.computeMacaroon(arg1, secretKey, identifier);
        }
        else {
            this.macaroon = arg1;
        }
    }
    static modify(macaroon) {
        return new MacaroonsBuilder(macaroon);
    }
    static create(location, secretKey, identifier) {
        return new MacaroonsBuilder(location, secretKey, identifier).getMacaroon();
    }
    static deserialize(serializedMacaroon) {
        return MacaroonsDeSerializer_1.default.deserialize(serializedMacaroon);
    }
    getMacaroon() {
        return this.macaroon;
    }
    add_first_party_caveat(caveat) {
        if (caveat !== undefined) {
            const caveatBuffer = new Buffer(caveat, MacaroonsConstants_1.default.IDENTIFIER_CHARSET);
            if (this.macaroon.caveatPackets.length + 1 > MacaroonsConstants_1.default.MACAROON_MAX_CAVEATS) {
                throw new Error(`Too many caveats. There are max. ${MacaroonsConstants_1.default.MACAROON_MAX_CAVEATS} caveats allowed.`);
            }
            const signature = CryptoTools_1.default.macaroon_hmac(this.macaroon.signatureBuffer, caveatBuffer);
            const caveatsExtended = this.macaroon.caveatPackets.concat(new CaveatPacket_1.default(CaveatPacketType_1.CaveatPacketType.cid, caveatBuffer));
            this.macaroon = new Macaroon_1.default(this.macaroon.location, this.macaroon.identifier, signature, caveatsExtended);
        }
        return this;
    }
    add_third_party_caveat(location, secret, identifier) {
        if (this.macaroon.caveatPackets.length + 1 > MacaroonsConstants_1.default.MACAROON_MAX_CAVEATS) {
            throw new Error(`Too many caveats. There are max. ${MacaroonsConstants_1.default.MACAROON_MAX_CAVEATS} caveats allowed.`);
        }
        const thirdPartyPacket = CryptoTools_1.default.macaroon_add_third_party_caveat_raw(this.macaroon.signatureBuffer, secret, identifier);
        const hash = thirdPartyPacket.signature;
        const caveatsExtended = this.macaroon.caveatPackets.concat(new CaveatPacket_1.default(CaveatPacketType_1.CaveatPacketType.cid, identifier), new CaveatPacket_1.default(CaveatPacketType_1.CaveatPacketType.vid, thirdPartyPacket.vidData), new CaveatPacket_1.default(CaveatPacketType_1.CaveatPacketType.cl, location));
        this.macaroon = new Macaroon_1.default(this.macaroon.location, this.macaroon.identifier, hash, caveatsExtended);
        return this;
    }
    prepare_for_request(macaroon) {
        const hash = CryptoTools_1.default.macaroon_bind(this.getMacaroon().signatureBuffer, macaroon.signatureBuffer);
        this.macaroon = new Macaroon_1.default(macaroon.location, macaroon.identifier, hash, macaroon.caveatPackets);
        return this;
    }
    computeMacaroon(location, key, identifier) {
        const tempKey = CryptoTools_1.default.generate_derived_key(key.toString());
        const signature = CryptoTools_1.default.macaroon_hmac(tempKey, identifier);
        return new Macaroon_1.default(location, identifier, signature);
    }
}
exports.default = MacaroonsBuilder;
//# sourceMappingURL=MacaroonsBuilder.js.map