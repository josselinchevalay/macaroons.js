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

/// <reference path="../../typings/tsd.d.ts" />


import {createHmac} from 'crypto';
import {secret_box} from 'ecma-nacl';
import MacaroonsConstants from './MacaroonsConstants';
import ThirdPartyPacket from './ThirdPartyPacket';

const toBuffer:Function = require('typedarray-to-buffer');

// tslint:disable-next-line:no-default-export
export default class CryptoTools {

  public static generate_derived_key(variableKey:string):Buffer {
    const MACAROONS_MAGIC_KEY = new Buffer("macaroons-key-generator", "utf-8");
  
    return CryptoTools.macaroon_hmac(MACAROONS_MAGIC_KEY, new Buffer(variableKey, MacaroonsConstants.IDENTIFIER_CHARSET));
  }

  
  public static macaroon_hmac(key:Buffer, message:string|Buffer):Buffer {
    if (typeof message === undefined) { throw new Error("Missing second parameter 'message'."); }
    
    const mac = createHmac('sha256', key);
    if (typeof message === 'string') {
      mac.update(new Buffer(message, MacaroonsConstants.IDENTIFIER_CHARSET));
    } else {
      mac.update(message);
    }

    return mac.digest();
  }

  public static macaroon_hash2(key:Buffer, message1:Buffer, message2:Buffer):Buffer {
    const tmp = new Buffer(MacaroonsConstants.MACAROON_HASH_BYTES * 2);
    CryptoTools.macaroon_hmac(key, message1).copy(tmp, 0, 0, MacaroonsConstants.MACAROON_HASH_BYTES);
    CryptoTools.macaroon_hmac(key, message2).copy(tmp, MacaroonsConstants.MACAROON_HASH_BYTES, 0, MacaroonsConstants.MACAROON_HASH_BYTES);

    return CryptoTools.macaroon_hmac(key, tmp);
  }

  public static macaroon_add_third_party_caveat_raw(oldSig:Buffer, key:string, identifier:string):ThirdPartyPacket {
    const derivedKey:Buffer = CryptoTools.generate_derived_key(key);

    const encNonce:Buffer = new Buffer(MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES);
    encNonce.fill(0);
    // XXX get some random bytes instead
    const encPlaintext:Buffer = new Buffer(MacaroonsConstants.MACAROON_HASH_BYTES);
    encPlaintext.fill(0);
    // now encrypt the key to give us vid
    derivedKey.copy(encPlaintext, 0, 0, MacaroonsConstants.MACAROON_HASH_BYTES);

    const encCiphertext = CryptoTools.macaroon_secretbox(oldSig, encNonce, encPlaintext);

    const vid:Buffer = new Buffer(MacaroonsConstants.VID_NONCE_KEY_SZ);
    vid.fill(0);
    encNonce.copy(vid, 0, 0, MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES);
    encCiphertext.copy(vid, MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES, 0, MacaroonsConstants.VID_NONCE_KEY_SZ - MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES);

    const newSig:Buffer = CryptoTools.macaroon_hash2(oldSig, vid, new Buffer(identifier, MacaroonsConstants.IDENTIFIER_CHARSET));
    
    return new ThirdPartyPacket(newSig, vid);
  }

  public static macaroon_bind(Msig:Buffer, MPsig:Buffer):Buffer {
    const key:Buffer = new Buffer(MacaroonsConstants.MACAROON_HASH_BYTES);
    key.fill(0);
    
    return CryptoTools.macaroon_hash2(key, Msig, MPsig);
  }

  public static macaroon_secretbox(key:Buffer, nonce:Buffer, plaintext:Buffer):Buffer {
    const cipherBytes = secret_box.pack(new Uint8Array(<any>plaintext), new Uint8Array(<any>nonce), new Uint8Array(<any>key));
    
    return toBuffer(cipherBytes);
  }

  public static macaroon_secretbox_open(encKey:Buffer, encNonce:Buffer, ciphertext:Buffer):Buffer {
    const plainBytes = secret_box.open(new Uint8Array(<any>ciphertext), new Uint8Array(<any>encNonce), new Uint8Array(<any>encKey));
    
    return toBuffer(plainBytes);
  }

}