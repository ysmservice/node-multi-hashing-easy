const multiHashing = require('../build/Release/multihashing');
const assert = require('assert');

var cn_data = new Buffer("6465206f6d6e69627573206475626974616e64756d", "hex");
var cnv1_data = new Buffer("0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02", "hex");
var cn_hash = new Buffer("2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5", "hex");
var cnv1_hash = new Buffer("c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122", "hex");

hashedData = multiHashing['cryptonight'](cn_data);
hashedData_v1 = multiHashing['cryptonight'](cnv1_data, 1);

console.log(hashedData);
console.log(hashedData_v1);

assert.deepEqual(hashedData, cn_hash);
assert.deepEqual(hashedData_v1, cnv1_hash);
