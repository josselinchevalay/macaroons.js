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
import Macaroon from '../../main/ts/Macaroon';
import MacaroonsBuilder from '../../main/ts/MacaroonsBuilder';
import MacaroonsVerifier from '../../main/ts/MacaroonsVerifier';
import TimestampCaveatVerifier from '../../main/ts/verifier/TimestampCaveatVerifier';



describe('MacaroonsPrepareRequestAndVerifyTest', () => {

  let identifier;
  let secret;
  let location;
  let caveatKey;
  let publicIdentifier;
  let predicate;
  let m:Macaroon;
  let dp:Macaroon;
  let d:Macaroon;

  function setup() {
    secret = "this is a different super-secret key; never use the same secret twice";
    publicIdentifier = "we used our other secret key";
    location = "http://mybank/";
    m = new MacaroonsBuilder(location, secret, publicIdentifier)
        .add_first_party_caveat("account = 3735928559")
        .getMacaroon();
    expect(m.signature).to.equal("1434e674ad84fdfdc9bc1aa00785325c8b6d57341fc7ce200ba4680c80786dda");

    caveatKey = "4; guaranteed random by a fair toss of the dice";
    predicate = "user = Alice";
    identifier = send_to_auth_and_recv_identifier(caveatKey, predicate);

    m = new MacaroonsBuilder(m)
        .add_third_party_caveat("http://auth.mybank/", caveatKey, identifier)
        .getMacaroon();
    expect(m.signature).to.equal("d27db2fd1f22760e4c3dae8137e2d8fc1df6c0741c18aed4b97256bf78d1f55c");
  }

  // tslint:disable-next-line:no-shadowed-variable
  function send_to_auth_and_recv_identifier(_caveatKey:string, _predicate:string) {

    return "this was how we remind auth of key/pred";
  }

  function preparing_a_macaroon_for_request() {
    setup();

    caveatKey = "4; guaranteed random by a fair toss of the dice";
    identifier = "this was how we remind auth of key/pred";
    d = new MacaroonsBuilder("http://auth.mybank/", caveatKey, identifier)
        .add_first_party_caveat("time < 2025-01-01T00:00")
        .getMacaroon();
    expect(d.signature).to.equal("b338d11fb136c4b95c86efe146f77978cd0947585375ba4d4da4ef68be2b3e8b");

    dp = new MacaroonsBuilder(m)
        .prepare_for_request(d)
        .getMacaroon();

    expect(dp.signature).to.equal("f8718cd3d2cc250344c072ea557c36a4f5a963353a5b664b0faa709e0d65ad9f");
  }


  it("test#1 preparing a macaroon for request", () => {
    setup();
    preparing_a_macaroon_for_request();
  });


  it("verifying_valid", () => {
    setup();
    preparing_a_macaroon_for_request();

    const valid = new MacaroonsVerifier(m)
        .satisfyExact("account = 3735928559")
        .satisfyGeneral(TimestampCaveatVerifier)
        .satisfy3rdParty(dp)
        .isValid(secret);

    expect(valid).to.equal(true);
  });


  it("verifying with wrong secret -> has to fail, but no exceptions", () => {
    setup();
    preparing_a_macaroon_for_request();

    let valid = new MacaroonsVerifier(m)
        .satisfyExact("account = 3735928559")
        .satisfyGeneral(TimestampCaveatVerifier)
        .satisfy3rdParty(dp)
        .isValid("wrong secret");

    expect(valid).to.equal(false);
  });


  it("verifying unprepared macaroon -> has to fail", () => {
    setup();
    preparing_a_macaroon_for_request();

    let valid = new MacaroonsVerifier(m)
        .satisfyExact("account = 3735928559")
        .satisfyGeneral(TimestampCaveatVerifier)
        .satisfy3rdParty(d)
        .isValid(secret);

    expect(valid).to.equal(false);
  });


  it("verifying macaroon without satisfying 3rd party -> has to fail", () => {
    setup();
    preparing_a_macaroon_for_request();

    let valid = new MacaroonsVerifier(m)
        .satisfyExact("account = 3735928559")
        .satisfyGeneral(TimestampCaveatVerifier)
        .isValid(secret);

    expect(valid).to.equal(false);
  });

});