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
import BufferTools from './BufferTools';
import CaveatPacket from './CaveatPacket';
import {CaveatPacketType} from './CaveatPacketType';
import CryptoTools from './CryptoTools';
import Macaroon from './Macaroon';
import MacaroonsConstants from './MacaroonsConstants';

/**
 * Used to verify Macaroons
 */
export default class MacaroonsVerifier {

  private predicates:string[] = [];
  private boundMacaroons:Macaroon[] = [];
  private generalCaveatVerifiers:IGeneralCaveatVerifier[] = [];
  private macaroon:Macaroon;

  constructor(macaroon:Macaroon) {
    this.macaroon = macaroon;
  }

  private static containsElement(elements:string[], anElement:string):boolean {
    if(elements !== null && elements.filter(e => e === anElement).length > 0) {
      return true
    }

    return false;
 }

  /**
   * @param secret a Buffer, that will be used, a minimum length of {@link MacaroonsConstants.MACAROON_SUGGESTED_SECRET_LENGTH} is highly recommended
   * @throws Error if macaroon isn't valid
   */
  public assertIsValid(secret:string|Buffer):void {
    const secretBuffer = (secret instanceof Buffer) ? secret : CryptoTools.generate_derived_key(secret);
    const result = this.isValid_verify_raw(this.macaroon, secretBuffer);
    if (result.fail) {
      const msg = result.failMessage !== undefined ? result.failMessage : "This macaroon isn't valid.";
      throw new Error(msg);
    }
  }

  /**
   * @param secret string this secret will be enhanced, in case it's shorter than {@link MacaroonsConstants.MACAROON_SUGGESTED_SECRET_LENGTH}
   * @return true/false if the macaroon is valid
   */
  public isValid(secret:string|Buffer):boolean {
    const secretBuffer =  CryptoTools.generate_derived_key(secret.toString());
    
    return !this.isValid_verify_raw(this.macaroon, secretBuffer).fail;
  }

  /**
   * Caveats like these are called "exact caveats" because there is exactly one way
   * to satisfy them.  Either the given caveat matches, or it doesn't.  At
   * verification time, the verifier will check each caveat in the macaroon against
   * the list of satisfied caveats provided to satisfyExact(String).
   * When it finds a match, it knows that the caveat holds and it can move onto the next caveat in
   * the macaroon.
   *
   * @param caveat caveat
   * @return this {@link MacaroonsVerifier}
   */
  public satisfyExact(caveat:string):MacaroonsVerifier {
    if (caveat) {
      this.predicates.push(caveat);
    }

    return this;
  }

  /**
   * Binds a prepared macaroon.
   *
   * @param preparedMacaroon preparedMacaroon
   * @return this {@link MacaroonsVerifier}
   */
  public satisfy3rdParty(preparedMacaroon:Macaroon):MacaroonsVerifier {
    if (preparedMacaroon) {
      this.boundMacaroons.push(preparedMacaroon);
    }

    return this;
  }

  /**
   * Another technique for informing the verifier that a caveat is satisfied
   * allows for expressive caveats. Whereas exact caveats are checked
   * by simple byte-wise equality, general caveats are checked using
   * an application-provided callback that returns true if and only if the caveat
   * is true within the context of the request.
   * There's no limit on the contents of a general caveat,
   * so long as the callback understands how to determine whether it is satisfied.
   * This technique is called "general caveats".
   *
   * @param generalVerifier generalVerifier a function(caveat:string):boolean which does the verification
   * @return this {@link MacaroonsVerifier}
   */
  public satisfyGeneral(generalVerifier:(caveat:string)=>boolean):MacaroonsVerifier {
    if (generalVerifier) {
      this.generalCaveatVerifiers.push(generalVerifier);
    }

    return this;
  }

  private isValid_verify_raw(M:Macaroon, secret:Buffer):VerificationResult {
    let vresult = this.macaroon_verify_inner(M, secret);
    if (!vresult.fail) {
      vresult.fail = !BufferTools.equals(vresult.csig, this.macaroon.signatureBuffer);
      if (vresult.fail) {
        vresult = new VerificationResult("Verification failed. Signature doesn't match. Maybe the key was wrong OR some caveats aren't satisfied.");
      }
    }
    
    return vresult;
  }

  private macaroon_verify_inner(M:Macaroon, key:Buffer):VerificationResult {
    let csig:Buffer = CryptoTools.macaroon_hmac(key, M.identifier);

    if (M.caveatPackets !== undefined) {
      const caveatPackets:CaveatPacket[] = M.caveatPackets;
      for (let i = 0; i < caveatPackets.length; i++) {
        const caveat = caveatPackets[i];
        if (caveat === undefined) { continue; }
        if (caveat.type === CaveatPacketType.cl) { continue; }
        if (!(caveat.type === CaveatPacketType.cid && caveatPackets[Math.min(i + 1, caveatPackets.length - 1)].type === CaveatPacketType.vid)) {
          if (MacaroonsVerifier.containsElement(this.predicates, caveat.getValueAsText()) || this.verifiesGeneral(caveat.getValueAsText())) {
            csig = CryptoTools.macaroon_hmac(csig, caveat.rawValue);
          }
        } else {
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
          csig = CryptoTools.macaroon_hash2(csig, vdata, data);
        }
      }
    }

    return new VerificationResult(csig);
  }

  private macaroon_verify_inner_3rd(M:Macaroon, C:CaveatPacket, sig:Buffer):boolean {
    if (!M) { return false; }
    let encPlaintext = new Buffer(MacaroonsConstants.MACAROON_SECRET_TEXT_ZERO_BYTES + MacaroonsConstants.MACAROON_HASH_BYTES);
    const encCipherText = new Buffer(MacaroonsConstants.MACAROON_HASH_BYTES + MacaroonsConstants.SECRET_BOX_OVERHEAD);
    encPlaintext.fill(0);
    encCipherText.fill(0);

    const vidData = C.rawValue;
    //assert vidData.length == VID_NONCE_KEY_SZ;
    /**
     * the nonce is in the first MACAROON_SECRET_NONCE_BYTES
     * of the vid; the ciphertext is in the rest of it.
     */
    const encNonce = new Buffer(MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES);
    vidData.copy(encNonce, 0, 0, encNonce.length);

    // fill in the ciphertext 
    vidData.copy(encCipherText, 0, MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES, MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES + vidData.length - MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES);
    try {
      encPlaintext = CryptoTools.macaroon_secretbox_open(sig, encNonce, encCipherText);
    }
    catch (error) {
      if (/Cipher bytes fail verification/.test(error.message)) {
        return false;
      } else {
        throw new Error(`Error while deciphering 3rd party caveat, msg=${error}`);
      }
    }
    const key = new Buffer(MacaroonsConstants.MACAROON_HASH_BYTES);
    key.fill(0);
    encPlaintext.copy(key, 0, 0, MacaroonsConstants.MACAROON_HASH_BYTES);
    const vresult = this.macaroon_verify_inner(M, key);

    const data = this.macaroon.signatureBuffer;
    const csig = CryptoTools.macaroon_bind(data, vresult.csig);

    return BufferTools.equals(csig, M.signatureBuffer);
  }

  private findBoundMacaroon(identifier:string):Macaroon {
    for (let i = 0; i < this.boundMacaroons.length; i++) {
      const boundMacaroon = this.boundMacaroons[i];
      if (identifier === boundMacaroon.identifier) {
        return boundMacaroon;
      }
    }

    return undefined;
  }

  private verifiesGeneral(caveat:string):boolean {
    let found:boolean = false;
    for (var i = 0; i < this.generalCaveatVerifiers.length; i++) {
     const verifier:IGeneralCaveatVerifier = this.generalCaveatVerifiers[i];
      found = found || verifier(caveat);
    }

    return found;
  }

}


class VerificationResult {
  public csig:Buffer = null;
  public fail:boolean = false;
  public failMessage:string = null;

  constructor(arg:Buffer|string) {
    if (typeof arg === 'string') {
      this.failMessage = arg;
      this.fail = true;
    } else if (typeof arg === 'object') {
      this.csig = arg;
    }
  }

}


interface IGeneralCaveatVerifier {
  /**
   * @param caveat caveat
   * @return True, if this caveat is satisfies the applications requirements. False otherwise.
   */
  (caveat:string):boolean;
}