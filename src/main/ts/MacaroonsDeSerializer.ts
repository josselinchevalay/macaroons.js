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
import Base64Tools from './Base64Tools';
import CaveatPacket from './CaveatPacket';
import {CaveatPacketType} from './CaveatPacketType';
import Macaroon from './Macaroon';
import MacaroonsConstants from './MacaroonsConstants';



 export default class MacaroonsDeSerializer {

  public static deserialize(serializedMacaroon:string):Macaroon {
    const data = new Buffer(Base64Tools.transformBase64UrlSafe2Base64(serializedMacaroon), 'base64');
    const minLength = MacaroonsConstants.MACAROON_HASH_BYTES + MacaroonsConstants.KEY_VALUE_SEPARATOR_LEN + MacaroonsConstants.SIGNATURE.length;
    if (data.length < minLength) {
      throw new Error(`Couldn't deserialize macaroon. Not enough bytes for signature found. There have to be at least ${minLength} bytes`);
    }

    return MacaroonsDeSerializer.deserializeStream(new StatefulPacketReader(data));
  }

private static deserializeStream(packetReader:StatefulPacketReader):Macaroon {
    let location:string = "";
    let identifier:string = "";
    const caveats:CaveatPacket[] = [];
    // tslint:disable-next-line:no-null-keyword
    let signature:Buffer = null;
    let s;
    let raw;
    /*let packet:Packet;
    packet = MacaroonsDeSerializer.readPacket(packetReader)
    while( packet !== null) {*/
    for (let packet:Packet; (packet = MacaroonsDeSerializer.readPacket(packetReader)) !== undefined;) {
      if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants.LOCATION_BYTES)) {
        location = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants.LOCATION_BYTES);
      } else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants.IDENTIFIER_BYTES)) {
        identifier = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants.IDENTIFIER_BYTES);
      } else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants.CID_BYTES)) {
        s = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants.CID_BYTES);
        caveats.push(new CaveatPacket(CaveatPacketType.cid, s));
      } else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants.CL_BYTES)) {
        s = MacaroonsDeSerializer.parsePacket(packet, MacaroonsConstants.CL_BYTES);
        caveats.push(new CaveatPacket(CaveatPacketType.cl, s));
      } else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants.VID_BYTES)) {
        raw = MacaroonsDeSerializer.parseRawPacket(packet, MacaroonsConstants.VID_BYTES);
        caveats.push(new CaveatPacket(CaveatPacketType.vid, raw));
      } else if (MacaroonsDeSerializer.bytesStartWith(packet.data, MacaroonsConstants.SIGNATURE_BYTES)) {
        signature = MacaroonsDeSerializer.parseSignature(packet, MacaroonsConstants.SIGNATURE_BYTES);
      }
    }
    
    return new Macaroon(location, identifier, signature, caveats);
  }

  private static parseSignature(packet:Packet, signaturePacketData:Buffer):Buffer {
    const headerLen = signaturePacketData.length + MacaroonsConstants.KEY_VALUE_SEPARATOR_LEN;
    const len = Math.min(packet.data.length - headerLen, MacaroonsConstants.MACAROON_HASH_BYTES);
    const signature = new Buffer(len);
    packet.data.copy(signature, 0, headerLen, headerLen + len);
   
    return signature;
  }

  private static parsePacket(packet:Packet, header:Buffer):string {
    const headerLen = header.length + MacaroonsConstants.KEY_VALUE_SEPARATOR_LEN;
    let len = packet.data.length - headerLen;
    if (packet.data[headerLen + len - 1] === MacaroonsConstants.LINE_SEPARATOR) { len--; }
    
    return packet.data.toString(MacaroonsConstants.IDENTIFIER_CHARSET, headerLen, headerLen + len);
  }

  private static parseRawPacket(packet:Packet, header:Buffer):Buffer {
    const headerLen = header.length + MacaroonsConstants.KEY_VALUE_SEPARATOR_LEN;
    const len = packet.data.length - headerLen - MacaroonsConstants.LINE_SEPARATOR_LEN;
    const raw = new Buffer(len);
    packet.data.copy(raw, 0, headerLen, headerLen + len);
    
    return raw;
  }

  private static bytesStartWith(bytes:Buffer, startBytes:Buffer):boolean {
    if (bytes.length < startBytes.length) { return false; }
    for (let i = 0, len = startBytes.length; i < len; i++) {
      if (bytes[i] !== startBytes[i]) { return false; }
    }
    
    return true;
  }

  private static readPacket(stream:StatefulPacketReader):Packet {
    if (stream.isEOF()) { return undefined; }
    if (!stream.isPacketHeaderAvailable()) {
      throw new Error(`Not enough header bytes available. Needed ${MacaroonsConstants.PACKET_PREFIX_LENGTH} bytes.`);
    }
    const size = stream.readPacketHeader();
    //assert size <= PACKET_MAX_SIZE;
    const data = new Buffer(size - MacaroonsConstants.PACKET_PREFIX_LENGTH);
    const read = stream.read(data);
    if (read < 0) { return undefined; }
    if (read !== data.length) {
      throw new Error(`Not enough data bytes available. Needed ${data.length} bytes, but was only  ${read}`);
    }

    return new Packet(size, data);
  }

}


class Packet {
  public size:number;
  public data:Buffer;

  constructor(size:number, data:Buffer) {
    this.size = size;
    this.data = data;
  }
}


class StatefulPacketReader {
  private static HEX_ALPHABET:number[] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  private buffer:Buffer;
  private seekIndex:number = 0;

  constructor(buffer:Buffer) {
    this.buffer = buffer;
  }

  public read(data:Buffer):number {
    const len = Math.min(data.length, this.buffer.length - this.seekIndex);
    if (len > 0) {
      this.buffer.copy(data, 0, this.seekIndex, this.seekIndex + len);
      this.seekIndex += len;
      
      return len;
    }
    
    return -1;
  }

  public readPacketHeader():number {
    return (StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]] << 12)
        | (StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]] << 8)
        | (StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]] << 4)
        | StatefulPacketReader.HEX_ALPHABET[this.buffer[this.seekIndex++]];
  }

  public isPacketHeaderAvailable():boolean {
    return this.seekIndex <= (this.buffer.length - MacaroonsConstants.PACKET_PREFIX_LENGTH);
  }

  public isEOF():boolean {
    return !(this.seekIndex < this.buffer.length);
  }
}
