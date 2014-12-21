/*
 * Copyright 2014 Martin W. Kirst
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var CaveatPacketType = require('./CaveatPacketType');
var MacaroonsSerializer = (function () {
    function MacaroonsSerializer() {
    }
    MacaroonsSerializer.serialize = function (macaroon) {
        var packets = [];
        packets.push(MacaroonsSerializer.serialize_packet(0 /* location */, macaroon.location));
        packets.push(MacaroonsSerializer.serialize_packet(1 /* identifier */, macaroon.identifier));
        //  for (CaveatPacket caveatPacket : macaroon.caveatPackets) {
        //    packets.add(serialize_packet(caveatPacket.type, caveatPacket.rawValue));
        //  }
        packets.push(MacaroonsSerializer.serialize_packet_buf(2 /* signature */, macaroon.signatureBuffer));
        var base64 = MacaroonsSerializer.flattenByteArray(packets).toString("base64");
        return MacaroonsSerializer.encodeBase64UrlSafe(base64);
    };
    MacaroonsSerializer.serialize_packet = function (type, data) {
        return MacaroonsSerializer.serialize_packet_buf(type, new Buffer(data, this.IDENTIFIER_CHARSET));
    };
    MacaroonsSerializer.serialize_packet_buf = function (type, data) {
        var typname = CaveatPacketType[type];
        var packet_len = MacaroonsSerializer.PACKET_PREFIX_LENGTH + typname.length + MacaroonsSerializer.KEY_VALUE_SEPARATOR_LEN + data.length + MacaroonsSerializer.LINE_SEPARATOR_LEN;
        var packet = new Buffer(packet_len);
        packet.fill(0);
        var offset = 0;
        MacaroonsSerializer.packet_header(packet_len).copy(packet, 0, 0);
        offset += MacaroonsSerializer.PACKET_PREFIX_LENGTH;
        new Buffer(typname, 'ascii').copy(packet, offset, 0);
        offset += typname.length;
        packet[offset] = MacaroonsSerializer.KEY_VALUE_SEPARATOR;
        offset += MacaroonsSerializer.KEY_VALUE_SEPARATOR_LEN;
        data.copy(packet, offset, 0);
        offset += data.length;
        packet[offset] = MacaroonsSerializer.LINE_SEPARATOR;
        return packet;
    };
    MacaroonsSerializer.packet_header = function (size) {
        // assert.ok(size < 65536, "size < 65536");
        var size = (size & 0xffff);
        var packet = new Buffer(MacaroonsSerializer.PACKET_PREFIX_LENGTH);
        packet[0] = MacaroonsSerializer.HEX[(size >> 12) & 15];
        packet[1] = MacaroonsSerializer.HEX[(size >> 8) & 15];
        packet[2] = MacaroonsSerializer.HEX[(size >> 4) & 15];
        packet[3] = MacaroonsSerializer.HEX[(size) & 15];
        return packet;
    };
    MacaroonsSerializer.flattenByteArray = function (bufs) {
        var size = 0;
        for (var i = 0; i < bufs.length; i++) {
            size += bufs[i].length;
        }
        var result = new Buffer(size);
        size = 0;
        for (var i = 0; i < bufs.length; i++) {
            bufs[i].copy(result, size, 0);
            size += bufs[i].length;
        }
        return result;
    };
    MacaroonsSerializer.encodeBase64UrlSafe = function (base64) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    MacaroonsSerializer.HEX = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66];
    MacaroonsSerializer.IDENTIFIER_CHARSET = "utf8";
    MacaroonsSerializer.PACKET_PREFIX_LENGTH = 4;
    MacaroonsSerializer.LINE_SEPARATOR = '\n'.charCodeAt(0);
    MacaroonsSerializer.LINE_SEPARATOR_LEN = 1;
    MacaroonsSerializer.KEY_VALUE_SEPARATOR = ' '.charCodeAt(0);
    MacaroonsSerializer.KEY_VALUE_SEPARATOR_LEN = 1;
    return MacaroonsSerializer;
})();
module.exports = MacaroonsSerializer;