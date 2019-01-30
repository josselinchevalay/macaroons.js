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

// tslint:disable-next-line:no-implicit-dependencies
import {expect} from 'chai';
import Macaroon from '../../main/ts/Macaroon';
import MacaroonsBuilder from '../../main/ts/MacaroonsBuilder';
import MacaroonsVerifier from '../../main/ts/MacaroonsVerifier';
import TimestampCaveatVerifier from '../../main/ts/verifier/TimestampCaveatVerifier';

describe('MacaroonsVerifierTest',  () => {

  const location:string = 'http://mybank/';
  let secret:any = 'this is our super secret key; only we should know it';
  const identifier:string = 'we used our secret key';


  it("verify a valid Macaroon with secret string",  () => {
    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier).getMacaroon();
    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);

    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secret)).to.equal(true);
  });


  it("verify a valid Macaroon with secret Buffer", () => {
    const secretBuffer:Buffer = new Buffer(secret, 'ascii');
    const m:Macaroon = new MacaroonsBuilder(location, secretBuffer, identifier).getMacaroon();
    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);

    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secretBuffer)).to.equal(true);
  });


 /* it("verify a valid Macaroon with assertion with secret string", () => {
    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier).getMacaroon();
    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);

    expect(verifier.assertIsValid.bind(verifier)).withArgs(secret).to.not.throwException();
  });*/


  /*it("verify a valid Macaroon with assertion with secret Buffer",  () => {
    secret = new Buffer(secret, 'ascii');
    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier).getMacaroon();
    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);

    expect(verifier.assertIsValid.bind(verifier)).withArgs(secret).to.not.throwException();
  });*/


  it("verify an invalid Macaroon", () => {
    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier).getMacaroon();
    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);

    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid("wrong secret")).to.equal(false);
  });


  /*it("verify an invalid Macaroon with assertion", () => {
    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier).getMacaroon();
    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);

    expect(verifier.assertIsValid).withArgs("wrong secret").to.throwException();
  });*/


  it("verification satisfy exact first party caveat", () => {
    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier)
        .add_first_party_caveat("account = 3735928559")
        .getMacaroon();

    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);
    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secret)).to.equal(false);

    verifier.satisfyExact("account = 3735928559");
    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secret)).to.equal(true);
  });


  it("verification satisfy exact attenuate with additional caveats", () => {
    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier)
        .add_first_party_caveat("account = 3735928559")
        .getMacaroon();

    const verifier:MacaroonsVerifier = new MacaroonsVerifier(m);
    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secret)).to.equal(false);

    verifier.satisfyExact("account = 3735928559");
    verifier.satisfyExact("IP = 127.0.0.1')");
    verifier.satisfyExact("browser = Chrome')");
    verifier.satisfyExact("action = deposit");
    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secret)).to.equal(true);
  });


  it("verification general", () => {
    const m = new MacaroonsBuilder(location, secret, identifier)
        .add_first_party_caveat("time < 2020-12-31T18:23:45Z")
        .getMacaroon();

    const verifier = new MacaroonsVerifier(m);
    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secret)).to.equal(false);

    verifier.satisfyGeneral(TimestampCaveatVerifier);
    // tslint:disable-next-line:chai-vague-errors
    expect(verifier.isValid(secret)).to.equal(true);
  });

});