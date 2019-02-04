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
import CaveatPacket from './CaveatPacket';
import {CaveatPacketType} from './CaveatPacketType';
import MacaroonsConstants from './MacaroonsConstants';
import MacaroonsSerializer from './MacaroonsSerializer';


/**
 * <p>
 * Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud
 * </p>
 * This is an immutable and serializable object.
 * Use {@link MacaroonsBuilder} to modify it.
 * Use {@link MacaroonsVerifier} to verify it.
 *
 * @see <a href="http://research.google.com/pubs/pub41892.html">http://research.google.com/pubs/pub41892.html</a>
 */
// tslint:disable-next-line:no-default-export
export default class Macaroon {

  public location:string;
  public identifier:string;
  public signature:string;
  public signatureBuffer:Buffer;

  public caveatPackets:CaveatPacket[] = [];

  constructor(location:string, identifier:string, signature:Buffer, caveats?:CaveatPacket[]) {
    this.identifier = identifier;
    this.location = location;
    this.signature = signature ? signature.toString('hex') : undefined;
    this.signatureBuffer = signature;
    this.caveatPackets = caveats ? caveats : [];
  }

  public serialize():string {
    return MacaroonsSerializer.serialize(this);
  }

  public inspect():string {
    return this.createKeyValuePacket(CaveatPacketType.location, this.location)
        + this.createKeyValuePacket(CaveatPacketType.identifier, this.identifier)
        + this.createCaveatsPackets(this.caveatPackets)
        + this.createKeyValuePacket(CaveatPacketType.signature, this.signature);
  }

  private createKeyValuePacket(type:CaveatPacketType, value:string):string {
    return value !== undefined ? CaveatPacketType[type] + MacaroonsConstants.KEY_VALUE_SEPARATOR_STR + value + MacaroonsConstants.LINE_SEPARATOR_STR : "";
  }

  private createCaveatsPackets(caveats:CaveatPacket[]):string {
    if (caveats === undefined) { return ""; }
    let text = "";
    // tslint:disable-next-line:prefer-for-of
    for (let i = 0; i < caveats.length; i++) {
      const packet:CaveatPacket = caveats[i];
      text += this.createKeyValuePacket(packet.type, packet.getValueAsText());
    }
    
    return text;
  }
}
