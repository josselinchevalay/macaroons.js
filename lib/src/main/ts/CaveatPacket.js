"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Base64Tools_1 = require("./Base64Tools");
const CaveatPacketType_1 = require("./CaveatPacketType");
const MacaroonsConstants_1 = require("./MacaroonsConstants");
class CaveatPacket {
    constructor(type, value) {
        if (typeof value === 'undefined') {
            throw new Error("Missing second parameter 'value' from type 'string' or 'Buffer'");
        }
        this.type = type;
        if (typeof value === 'string') {
            this.rawValue = new Buffer(value, MacaroonsConstants_1.default.IDENTIFIER_CHARSET);
        }
        else {
            this.rawValue = value;
        }
    }
    getRawValue() {
        return this.rawValue;
    }
    getValueAsText() {
        if (this.valueAsText === undefined) {
            this.valueAsText = (this.type === CaveatPacketType_1.CaveatPacketType.vid)
                ? Base64Tools_1.default.encodeBase64UrlSafe(this.rawValue.toString('base64'))
                : this.rawValue.toString(MacaroonsConstants_1.default.IDENTIFIER_CHARSET);
        }
        return this.valueAsText;
    }
}
exports.default = CaveatPacket;
//# sourceMappingURL=CaveatPacket.js.map