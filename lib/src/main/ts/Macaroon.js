"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const CaveatPacketType_1 = require("./CaveatPacketType");
const MacaroonsConstants_1 = require("./MacaroonsConstants");
const MacaroonsSerializer_1 = require("./MacaroonsSerializer");
class Macaroon {
    constructor(location, identifier, signature, caveats) {
        this.caveatPackets = [];
        this.identifier = identifier;
        this.location = location;
        this.signature = signature ? signature.toString('hex') : undefined;
        this.signatureBuffer = signature;
        this.caveatPackets = caveats ? caveats : [];
    }
    serialize() {
        return MacaroonsSerializer_1.default.serialize(this);
    }
    inspect() {
        return this.createKeyValuePacket(CaveatPacketType_1.CaveatPacketType.location, this.location)
            + this.createKeyValuePacket(CaveatPacketType_1.CaveatPacketType.identifier, this.identifier)
            + this.createCaveatsPackets(this.caveatPackets)
            + this.createKeyValuePacket(CaveatPacketType_1.CaveatPacketType.signature, this.signature);
    }
    createKeyValuePacket(type, value) {
        return value !== undefined ? CaveatPacketType_1.CaveatPacketType[type] + MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR_STR + value + MacaroonsConstants_1.default.LINE_SEPARATOR_STR : "";
    }
    createCaveatsPackets(caveats) {
        if (caveats === undefined) {
            return "";
        }
        let text = "";
        for (let i = 0; i < caveats.length; i++) {
            const packet = caveats[i];
            text += this.createKeyValuePacket(packet.type, packet.getValueAsText());
        }
        return text;
    }
}
exports.default = Macaroon;
//# sourceMappingURL=Macaroon.js.map