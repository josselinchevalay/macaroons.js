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
import {expect} from 'chai';
import Base64Tools from '../../main/ts/Base64Tools';
import {CaveatPacketType} from '../../main/ts/CaveatPacketType';
import Macaroon from '../../main/ts/Macaroon';
import MacaroonsBuilder from '../../main/ts/MacaroonsBuilder';
import MacaroonsDeSerializer from '../../main/ts/MacaroonsDeSerializer';



describe('MacaroonDeSerializerTest', () => {

  const location:string = "http://mybank/";
  const secret:string = "this is our super secret key; only we should know it";
  const identifier:string = "we used our secret key";

  it("a macaroon can be de-serialized", () => {

    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier).getMacaroon();
    const serialized:string = m.serialize();

    const deserialized:Macaroon = MacaroonsDeSerializer.deserialize(serialized);

    expect(m.identifier).to.equal(deserialized.identifier);
    expect(m.location).to.equal(deserialized.location);
    expect(m.signature).to.equal(deserialized.signature);
  });

  it("a macaroon with caveats can be de-serialized", () => {

    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier)
      .add_first_party_caveat("test = first_party")
      .add_third_party_caveat("third_party_location", "third_party_key", "test = third_party")
      .getMacaroon();
    const serialized:string = m.serialize();

    const vidAsBase64:Buffer = new Buffer(Base64Tools.transformBase64UrlSafe2Base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANLvrJ16nNUxLJ18zzy+kqCJ3dX2JTjTWl4c/F1aFDVWUgQ5W3Klk3eC7SoOU7acF"), 'base64');

    const deserialized:Macaroon = MacaroonsDeSerializer.deserialize(serialized);

    expect(m.identifier).to.equal(deserialized.identifier);
    expect(m.location).to.equal(deserialized.location);
    expect(m.caveatPackets[0].type).to.equal(CaveatPacketType.cid);
    expect(m.caveatPackets[0].getValueAsText()).to.equal("test = first_party");
    expect(m.caveatPackets[1].type).to.equal(CaveatPacketType.cid);
    expect(m.caveatPackets[1].getValueAsText()).to.equal("test = third_party");
    expect(m.caveatPackets[2].type).to.equal(CaveatPacketType.vid);
    expect(m.caveatPackets[2].getRawValue().toString('base64')).to.equal(vidAsBase64.toString('base64'));
    expect(m.caveatPackets[3].type).to.equal(CaveatPacketType.cl);
    expect(m.caveatPackets[3].getValueAsText()).to.equal('third_party_location');
    expect(m.signature).to.equal(deserialized.signature);
  });

  /*it("to short base64 throws Error",  () => {
    // packet is: "123"
    expect(MacaroonsDeSerializer.deserialize).with.arg("MTIzDQo=").to.throwError(/.*Not enough bytes for signature found.);
  });*/

  /*it("invalid packet length throws Error",  () => {
    // packet is: "fffflocation http://mybank12345678901234567890.com"
    expect(MacaroonsDeSerializer.deserialize).withArgs("ZmZmZmxvY2F0aW9uIGh0dHA6Ly9teWJhbmsxMjM0NTY3ODkwMTIzNDU2Nzg5MC5jb20=")
        .to.throwError(/.*Not enough data bytes available.);
  });*/

});