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
import MacaroonsBuilder from '../../main/ts/MacaroonsBuilder';


describe('Macaroon builder', () => {
    const location:string = "http://mybank/";
    const identifier:string = "we used our secret key";
    const secret:string = "this is our super secret key; only we should know it";

    it("create a Macaroon and verify signature location and identfier using secret string", () => {
        const m = new MacaroonsBuilder(location, secret, identifier).getMacaroon();
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.signature).to.equal("e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f");
    });

    it("create a Macaroon and verify signature location and identfier using secret Buffer ", () => {
        const m = new MacaroonsBuilder(location, new Buffer(secret,'ascii'), identifier).getMacaroon();
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.signature).to.equal("e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f");
    });

    it("create a Macaroon with static helper function using secret string", () => {
        const m = MacaroonsBuilder.create(location, new Buffer(secret), identifier);
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.signature).to.equal("e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f");
    });

    it("create a Macaroon with static helper function using secret Buffer", () => {
        const m = MacaroonsBuilder.create(location, new Buffer(secret,'ascii'), identifier);
    
        expect(m.location).to.equal(location);
        expect(m.identifier).to.equal(identifier);
        expect(m.signature).to.equal("e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f");
    });

    it("create a Macaroon and inspect", () => {
        const inspect = MacaroonsBuilder.create(location, new Buffer(secret), identifier).inspect();
    
        expect(inspect).to.equal(
            "location http://mybank/\n" +
            "identifier we used our secret key\n" +
            "signature e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f\n"
        );
    });

    it("different locations doesnt change the signatures", () => {
        const m1 = new MacaroonsBuilder("http://location_ONE", secret, identifier).getMacaroon();
        const m2 = new MacaroonsBuilder("http://location_TWO", secret, identifier).getMacaroon();
    
        expect(m1.signature).to.equal(m2.signature);
    });
    
});