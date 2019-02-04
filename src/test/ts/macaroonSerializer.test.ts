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
import Macaroon from '../../main/ts/Macaroon';
import MacaroonsBuilder from '../../main/ts/MacaroonsBuilder';
import MacaroonsSerializer from '../../main/ts/MacaroonsSerializer';

describe('MacaroonSerializerTest', () => {

  const location:string = "http://mybank/";
  const secret:string = "this is our super secret key; only we should know it";
  const identifier:string = "we used our secret key";

  it("a macaroon can be serialized", () => {

    const m:Macaroon = new MacaroonsBuilder(location, secret, identifier).getMacaroon();

    expect(MacaroonsSerializer.serialize(m)).to.equal("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo");
    expect(MacaroonsSerializer.serialize(m)).to.equal(m.serialize());
  });

});