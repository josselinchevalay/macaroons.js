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
import {CaveatPacketType} from '../../main/ts/CaveatPacketType';
import MacaroonsBuilder from '../../main/ts/MacaroonsBuilder';
import Macaroon from '../../main/ts/Macaroon';

describe('MacaroonBuilderCaveatsTest', () => {

    const location:string = "http://mybank/";
    const identifier:string = "we used our secret key";
    const secret:string = "this is our super secret key; only we should know it";

    it("add first party caveat", () => {
        const m = new MacaroonsBuilder(location, secret, identifier)
            .add_first_party_caveat("account = 3735928559")
            .getMacaroon();
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.caveatPackets[0].getValueAsText()).to.equal("account = 3735928559");
        expect(m.signature).to.equal("1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128");
    });

    it("modify also copies first party caveats", () => {
        // given
        let m:Macaroon = new MacaroonsBuilder(location, secret, identifier)
            .add_first_party_caveat("account = 3735928559")
            .getMacaroon();
    
        // when
        m = MacaroonsBuilder.modify(m)
            .getMacaroon();
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.caveatPackets[0].getValueAsText()).to.equal("account = 3735928559");
        expect(m.signature).to.equal("1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128");
    });

    it("add first party caveat 3 times", () => {
        // given
        const m:Macaroon = new MacaroonsBuilder(location, secret, identifier)
            .add_first_party_caveat("account = 3735928559")
            .add_first_party_caveat("time < 2015-01-01T00:00")
            .add_first_party_caveat("email = alice@example.org")
            .getMacaroon();
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.caveatPackets[0].type).to.equal(CaveatPacketType.cid);
        expect(m.caveatPackets[0].getValueAsText()).to.equal("account = 3735928559");
        expect(m.caveatPackets[1].type).to.equal(CaveatPacketType.cid);
        expect(m.caveatPackets[1].getValueAsText()).to.equal("time < 2015-01-01T00:00");
        expect(m.caveatPackets[2].type).to.equal(CaveatPacketType.cid);
        expect(m.caveatPackets[2].getValueAsText()).to.equal("email = alice@example.org");
        expect(m.signature).to.equal("882e6d59496ed5245edb7ab5b8839ecd63e5d504e54839804f164070d8eed952");
    });

    it("add first party caveat German umlauts using UTF8 encoding", () => {
        // given
        let mb:MacaroonsBuilder = new MacaroonsBuilder(location, secret, identifier);
        mb = mb.add_first_party_caveat("\u00E4");
        mb = mb.add_first_party_caveat("\u00FC");
        mb = mb.add_first_party_caveat("\u00F6");
        const m:Macaroon = mb.getMacaroon();
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.caveatPackets[0].type).to.equal(CaveatPacketType.cid);
        expect(m.caveatPackets[0].getValueAsText()).to.equal("\u00E4");
        expect(m.caveatPackets[1].type).to.equal(CaveatPacketType.cid);
        expect(m.caveatPackets[1].getValueAsText()).to.equal("\u00FC");
        expect(m.caveatPackets[2].type).to.equal(CaveatPacketType.cid);
        expect(m.caveatPackets[2].getValueAsText()).to.equal("\u00F6");
        expect(m.signature).to.equal("e38cce985a627fbfaea3490ca184fb8c59ec2bd14f0adc3b5035156e94daa111");
    });

    it("add first party caveat null save", () => {
        // given
        const m:Macaroon = new MacaroonsBuilder(location, secret, identifier)
            .add_first_party_caveat(undefined)
            .getMacaroon();
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.signature).to.equal("e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f");
    });

    it("add first party caveat inspect", () => {
        // given
        const  m:Macaroon = new MacaroonsBuilder(location, secret, identifier)
            .add_first_party_caveat("account = 3735928559")
            .getMacaroon();
    
        const inspect = m.inspect();
    
        expect(inspect).to.equal(
            "location http://mybank/\n" +
            "identifier we used our secret key\n" +
            "cid account = 3735928559\n" +
            "signature 1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128\n"
        );
      });
    
});