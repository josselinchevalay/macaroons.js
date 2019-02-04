"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Base64Tools_1 = require("./Base64Tools");
const CaveatPacketType_1 = require("./CaveatPacketType");
const MacaroonsConstants_1 = require("./MacaroonsConstants");
class MacaroonsSerializer {
    static serialize(macaroon) {
        let packets = [];
        packets.push(MacaroonsSerializer.serialize_packet(CaveatPacketType_1.CaveatPacketType.location, macaroon.location), MacaroonsSerializer.serialize_packet(CaveatPacketType_1.CaveatPacketType.identifier, macaroon.identifier));
        packets = packets.concat(macaroon.caveatPackets.map((caveatPacket) => {
            return MacaroonsSerializer.serialize_packet_buf(caveatPacket.type, caveatPacket.rawValue);
        }));
        packets.push(MacaroonsSerializer.serialize_packet_buf(CaveatPacketType_1.CaveatPacketType.signature, macaroon.signatureBuffer));
        const base64 = MacaroonsSerializer.flattenByteArray(packets).toString("base64");
        return Base64Tools_1.default.encodeBase64UrlSafe(base64);
    }
    static serialize_packet(type, data) {
        return MacaroonsSerializer.serialize_packet_buf(type, new Buffer(data, MacaroonsConstants_1.default.IDENTIFIER_CHARSET));
    }
    static serialize_packet_buf(type, data) {
        const typname = CaveatPacketType_1.CaveatPacketType[type];
        const packetLength = MacaroonsConstants_1.default.PACKET_PREFIX_LENGTH + typname.length + MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR_LEN + data.length + MacaroonsConstants_1.default.LINE_SEPARATOR_LEN;
        const packet = new Buffer(packetLength);
        packet.fill(0);
        let offset = 0;
        MacaroonsSerializer.packet_header(packetLength).copy(packet, 0, 0);
        offset += MacaroonsConstants_1.default.PACKET_PREFIX_LENGTH;
        new Buffer(typname, 'ascii').copy(packet, offset, 0);
        offset += typname.length;
        packet[offset] = MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR;
        offset += MacaroonsConstants_1.default.KEY_VALUE_SEPARATOR_LEN;
        data.copy(packet, offset, 0);
        offset += data.length;
        packet[offset] = MacaroonsConstants_1.default.LINE_SEPARATOR;
        return packet;
    }
    static packet_header(size) {
        size = (size & 0xffff);
        const packet = new Buffer(MacaroonsConstants_1.default.PACKET_PREFIX_LENGTH);
        packet[0] = MacaroonsSerializer.HEX[(size >> 12) & 15];
        packet[1] = MacaroonsSerializer.HEX[(size >> 8) & 15];
        packet[2] = MacaroonsSerializer.HEX[(size >> 4) & 15];
        packet[3] = MacaroonsSerializer.HEX[(size) & 15];
        return packet;
    }
    static flattenByteArray(bufs) {
        let size = 0;
        for (let i = 0; i < bufs.length; i++) {
            size += bufs[i].length;
        }
        let result = new Buffer(size);
        size = 0;
        for (let i = 0; i < bufs.length; i++) {
            bufs[i].copy(result, size, 0);
            size += bufs[i].length;
        }
        return result;
    }
}
MacaroonsSerializer.HEX = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66];
exports.default = MacaroonsSerializer;
//# sourceMappingURL=MacaroonsSerializer.js.map