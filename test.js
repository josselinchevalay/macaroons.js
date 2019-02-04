var MacaroonsBuilder = require('./index').MacaroonsBuilder;

var location = "http://www.example.org";
var identifier = "we used our secret key";
var secretKey = new Buffer("39a630867921b61522892779c659934667606426402460f913c9171966e97775", 'hex');
var macaroon = MacaroonsBuilder.create(location, secretKey, identifier);
var serialized = macaroon.serialize();
var l = MacaroonsBuilder.deserialize(serialized);
console.log(l.inspect());