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
import CryptoTools from './CryptoTools';
import Macaroon from './Macaroon';
import MacaroonsConstants from './MacaroonsConstants';
import MacaroonsDeSerializer from './MacaroonsDeSerializer';

/**
 * Used to build and modify Macaroons
 */
export default class MacaroonsBuilder {

  private macaroon:Macaroon

  
  constructor(arg1:string|Macaroon, secretKey?:string|Buffer, identifier?:string) {
    if (typeof arg1 === 'string') {
      if (typeof secretKey !== 'string' && !(secretKey instanceof Buffer)) {
        throw new Error("The secret key has to be a simple string or an instance of Buffer.");
      }
      this.macaroon = this.computeMacaroon(arg1, secretKey, identifier);
    } else {
      this.macaroon = arg1;
    }
  }

  /**
   * @param macaroon macaroon
   * @return {@link MacaroonsBuilder}
   */
  public static modify(macaroon:Macaroon):MacaroonsBuilder {
    return new MacaroonsBuilder(macaroon);
  }

  /**
   * @param location   location
   * @param secretKey  a Buffer containing a secret
   * @param identifier identifier
   * @return {@link Macaroon}
   */
  public static create(location:string, secretKey:Buffer, identifier:string):Macaroon;
  public static create(location:string, secretKey:string|Buffer, identifier:string):Macaroon {
    return new MacaroonsBuilder(location, secretKey, identifier).getMacaroon();
  }

  /**
   * @param serializedMacaroon serializedMacaroon
   * @return {@link Macaroon}
   * @throws Error when serialized macaroon is not valid base64, length is to short or contains invalid packet data
   */
  public static deserialize(serializedMacaroon:string):Macaroon {
    return MacaroonsDeSerializer.deserialize(serializedMacaroon);
  }

  /**
   * @return a {@link Macaroon}
   */
  public getMacaroon():Macaroon {
    return this.macaroon;
  }

  /**
   * @param caveat caveat
   * @return this {@link MacaroonsBuilder}
   * @throws Error if there are more than {@link MacaroonsConstants.MACAROON_MAX_CAVEATS} caveats.
   */
  public add_first_party_caveat(caveat:string):MacaroonsBuilder {
    if (caveat !== undefined) {
      const caveatBuffer:Buffer = new Buffer(caveat, MacaroonsConstants.IDENTIFIER_CHARSET);
      //assert caveatBytes.length < MacaroonsConstants.MACAROON_MAX_STRLEN;
      if (this.macaroon.caveatPackets.length + 1 > MacaroonsConstants.MACAROON_MAX_CAVEATS) {
        throw new Error(`Too many caveats. There are max. ${MacaroonsConstants.MACAROON_MAX_CAVEATS} caveats allowed.`);
      }
      const signature = CryptoTools.macaroon_hmac(this.macaroon.signatureBuffer, caveatBuffer);
      const caveatsExtended = this.macaroon.caveatPackets.concat(new CaveatPacket(CaveatPacketType.cid, caveatBuffer));
      this.macaroon = new Macaroon(this.macaroon.location, this.macaroon.identifier, signature, caveatsExtended);
    }

    return this;
  }


  /**
   * @param location   location
   * @param secret     secret
   * @param identifier identifier
   * @return this {@link MacaroonsBuilder}
   * @throws Error if there are more than {@link MacaroonsConstants#MACAROON_MAX_CAVEATS} caveats.
   */
  public add_third_party_caveat(location:string, secret:string, identifier:string):MacaroonsBuilder {
    //assert location.length() < MACAROON_MAX_STRLEN;
    //assert identifier.length() < MACAROON_MAX_STRLEN;

    if (this.macaroon.caveatPackets.length + 1 > MacaroonsConstants.MACAROON_MAX_CAVEATS) {
      throw new Error(`Too many caveats. There are max. ${MacaroonsConstants.MACAROON_MAX_CAVEATS} caveats allowed.`);
    }
    const thirdPartyPacket = CryptoTools.macaroon_add_third_party_caveat_raw(this.macaroon.signatureBuffer, secret, identifier);
    const hash = thirdPartyPacket.signature;
    const caveatsExtended = this.macaroon.caveatPackets.concat(
        new CaveatPacket(CaveatPacketType.cid, identifier),
        new CaveatPacket(CaveatPacketType.vid, thirdPartyPacket.vidData),
        new CaveatPacket(CaveatPacketType.cl, location)
    );
    this.macaroon = new Macaroon(this.macaroon.location, this.macaroon.identifier, hash, caveatsExtended);
    
    return this;
  }

  /**
   * @param macaroon macaroon used for preparing a request
   * @return this {@link MacaroonsBuilder}
   * @throws Error
   */
  public prepare_for_request(macaroon:Macaroon):MacaroonsBuilder {
    //assert macaroon.signatureBytes.length > 0;
    //assert getMacaroon().signatureBytes.length > 0;
    const hash = CryptoTools.macaroon_bind(this.getMacaroon().signatureBuffer, macaroon.signatureBuffer);
    this.macaroon = new Macaroon(macaroon.location, macaroon.identifier, hash, macaroon.caveatPackets);
    
    return this;
  }

  private computeMacaroon(location:string, key:string|Buffer, identifier:string):Macaroon {
    const tempKey:Buffer =  CryptoTools.generate_derived_key(key.toString()) ;
    const signature:Buffer = CryptoTools.macaroon_hmac(tempKey, identifier);
    
    return new Macaroon(location, identifier, signature);
  }

}