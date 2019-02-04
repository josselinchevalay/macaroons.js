"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Base64Tools_1 = require("./Base64Tools");
const CaveatPacket_1 = require("./CaveatPacket");
const CaveatPacketType_1 = require("./CaveatPacketType");
const Macaroon_1 = require("./Macaroon");
const MacaroonsConstants_1 = require("./MacaroonsConstants");
class MacaroonsDeSerializer {
    static deserialize(serializedMacaroon) {
        const data = new Buffer(Base64Tools_1.default.transformBase64UrlSafe2Base64(serializedMacaroon), 'base64');
        const minLength = MacaroonsConstants_1.default.MACAROON_HASH_BYTES + MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR_LEN + MacaroonsConstants_1.default.SIGNATURE.length;
        if (data.length < minLength) {
            throw new Error(`Couldn't deserialize macaroon. Not enough bytes for signature found. There have to be at least ${minLength} bytes`);
        }
        return MacaroonsDeSerializer.deserializeStream(new StatefulPacketReader(data));
    }
    static deserializeStream(packetReader) {
        let location = "";
        let identifier = "";
        const caveats = [];
        let signature = null;
        let s;
        let raw;
        for (let packet; (packet = MacaroonsDeSerializer.readPacket(packetReader)) !== undefined;) {
            if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants_1.default.LOCATION_BYTES)) {
                location = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants_1.default.LOCATION_BYTES);
            }
            else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants_1.default.IDENTIFIER_BYTES)) {
                identifier = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants_1.default.IDENTIFIER_BYTES);
            }
            else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants_1.default.CID_BYTES)) {
                s = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants_1.default.CID_BYTES);
                caveats.push(new CaveatPacket_1.default(CaveatPacketType_1.CaveatPacketType.cid, s));
            }
            else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants_1.default.CL_BYTES)) {
                s = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants_1.default.CL_BYTES);
                caveats.push(new CaveatPacket_1.default(CaveatPacketType_1.CaveatPacketType.cl, s));
            }
            else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants_1.default.VID_BYTES)) {
                raw = MacaroonsDeSerializer.parseRawPacket(packet, MacaroonsConstants_1.default.VID_BYTES);
                caveats.push(new CaveatPacket_1.default(CaveatPacketType_1.CaveatPacketType.vid, raw));
            }
            else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants_1.default.SIGNATURE_BYTES)) {
                signature = MacaroonsDeSerializer.parseSignature(packet, MacaroonsConstants_1.default.SIGNATURE_BYTES);
            }
        }
        return new Macaroon_1.default(location, identifier, signature, caveats);
    }
    static parseSignature(packet, signaturePacketData) {
        const headerLen = signaturePacketData.length + MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR_LEN;
        const len = Math.min(packet.data.length - headerLen, MacaroonsConstants_1.default.MACAROON_HASH_BYTES);
        const signature = new Buffer(len);
        packet.data.copy(signature, 0, headerLen, headerLen + len);
        return signature;
    }
    static parsePacket(packet, header) {
        const headerLen = header.length + MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR_LEN;
        let len = packet.data.length - headerLen;
        if (packet.data[headerLen + len - 1] === MacaroonsConstants_1.default.LINE_SEPARATOR) {
            len--;
        }
        return packet.data.toString(MacaroonsConstants_1.default.IDENTIFIER_CHARSET, headerLen, headerLen + len);
    }
    static parseRawPacket(packet, header) {
        const headerLen = header.length + MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR_LEN;
        const len = packet.data.length - headerLen - MacaroonsConstants_1.default.LINE_SEPARATOR_LEN;
        const raw = new Buffer(len);
        packet.data.copy(raw, 0, headerLen, headerLen + len);
        return raw;
    }
    static bytesStartWith(bytes, startBytes) {
        if (bytes.length < startBytes.length) {
            return false;
        }
        for (let i = 0, len = startBytes.length; i < len; i++) {
            if (bytes[i] !== startBytes[i]) {
                return false;
            }
        }
        return true;
    }
    static readPacket(stream) {
        if (stream.isEOF()) {
            return undefined;
        }
        if (!stream.isPacketHeaderAvailable()) {
            throw new Error(`Not enough header bytes available. Needed ${MacaroonsConstants_1.default.PACKET_PREFIX_LENGTH} bytes.`);
        }
        const size = stream.readPacketHeader();
        const data = new Buffer(size - MacaroonsConstants_1.default.PACKET_PREFIX_LENGTH);
        const read = stream.read(data);
        if (read < 0) {
            return undefined;
        }
        if (read !== data.length) {
            throw new Error(`Not enough data bytes available. Needed ${data.length} bytes, but was only  ${read}`);
        }
        return new Packet(size, data);
    }
}
exports.default = MacaroonsDeSerializer;
class Packet {
    constructor(size, data) {
        this.size = size;
        this.data = data;
    }
}
class StatefulPacketReader {
    constructor(buffer) {
        this.seekIndex = 0;
        this.buffer = buffer;
    }
    read(data) {
        const len = Math.min(data.length, this.buffer.length - this.seekIndex);
        if (len > 0) {
            this.buffer.copy(data, 0, this.seekIndex, this.seekIndex + len);
            this.seekIndex += len;
            return len;
        }
        return -1;
    }
    readPacketHeader() {
        return (StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]] << 12)
            | (StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]] << 8)
            | (StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]] << 4)
            | StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]];
    }
    isPacketHeaderAvailable() {
        return this.seekIndex <= (this.buffer.length - MacaroonsConstants_1.default.PACKET_PREFIX_LENGTH);
    }
    isEOF() {
        return !(this.seekIndex < this.buffer.length);
    }
}
StatefulPacketReader.HEX_ALPHABET = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];
//# sourceMappingURL=MacaroonsDeSerializer.js.map