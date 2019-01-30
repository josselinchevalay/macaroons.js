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

import {expect} from 'chai';
import Base64Tools from '../../main/ts/Base64Tools';
import {CaveatPacketType} from '../../main/ts/CaveatPacketType';
import Macaroon from '../../main/ts/Macaroon';
import MacaroonsBuilder from '../../main/ts/MacaroonsBuilder';


describe('MacaroonsBuilder3rdPartyCaveatsTest', () => {

  const secret:string = "this is a different super-secret key; never use the same secret twice";
  const publicIdentifier:string = "we used our other secret key";
  const location:string = "http://mybank/";

  const caveatKey:string = "4; guaranteed random by a fair toss of the dice";
  const identifier:string = "this was how we remind auth of key/pred";

  const vidAsBase64:Buffer = new Buffer(Base64Tools.transformBase64UrlSafe2Base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA027FAuBYhtHwJ58FX6UlVNFtFsGxQHS7uD_w_dedwv4Jjw7UorCREw5rXbRqIKhr"), 'base64');

  it("add third party caveat", () => {
    const m:Macaroon = new MacaroonsBuilder(location, secret, publicIdentifier)
        .add_first_party_caveat("account = 3735928559")
        .add_third_party_caveat("http://auth.mybank/", caveatKey, identifier)
        .getMacaroon();


    expect(m.identifier).to.equal(publicIdentifier);
    expect(m.location).to.equal(location);
    expect(m.caveatPackets[0].type).to.equal(CaveatPacketType.cid);
    expect(m.caveatPackets[0].getValueAsText()).to.equal("account = 3735928559");
    expect(m.caveatPackets[1].type).to.equal(CaveatPacketType.cid);
    expect(m.caveatPackets[1].getValueAsText()).to.equal(identifier);
    expect(m.caveatPackets[2].type).to.equal(CaveatPacketType.vid);
    expect(m.caveatPackets[2].getRawValue().toString('base64')).to.equal(vidAsBase64.toString('base64'));
    expect(m.caveatPackets[3].type).to.equal(CaveatPacketType.cl);
    expect(m.caveatPackets[3].getValueAsText()).to.equal('http://auth.mybank/');
    expect(m.signature).to.equal("d27db2fd1f22760e4c3dae8137e2d8fc1df6c0741c18aed4b97256bf78d1f55c");
    expect(m.serialize()).to.equal("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMmNpZGVudGlmaWVyIHdlIHVzZWQgb3VyIG90aGVyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDMwY2lkIHRoaXMgd2FzIGhvdyB3ZSByZW1pbmQgYXV0aCBvZiBrZXkvcHJlZAowMDUxdmlkIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANNuxQLgWIbR8CefBV-lJVTRbRbBsUB0u7g_8P3XncL-CY8O1KKwkRMOa120aiCoawowMDFiY2wgaHR0cDovL2F1dGgubXliYW5rLwowMDJmc2lnbmF0dXJlINJ9sv0fInYOTD2ugTfi2Pwd9sB0HBiu1LlyVr940fVcCg");
  });


});