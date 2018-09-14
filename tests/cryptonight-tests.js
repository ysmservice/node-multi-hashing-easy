const Buffer = require('safe-buffer').Buffer
const multiHashing = require('../build/Release/multihashing')
const assert = require('assert')

var cndata = new Buffer('6465206f6d6e69627573206475626974616e64756d', 'hex')
var xmrigdata = new Buffer('0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02', 'hex')
var cnhash = new Buffer('2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5', 'hex')
var xmrigcnvariant1hash = new Buffer('c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122', 'hex')
var xmrigcnlitehash = new Buffer('28a22bad3f93d1408fca472eb5ad1cbe75f21d053c8ce5b3af105a57713e21dd', 'hex')
var xmrigcnlitevariant1hash = new Buffer('87c4e570653eb4c2b42b7a0d546559452dfab573b82ec52f152b7ff98e79446f', 'hex')

var hashedData = multiHashing['cryptonight'](cndata)
var cnvariant1Data = multiHashing['cryptonight'](xmrigdata, 1)
var cnlitedata = multiHashing['cryptonight-lite'](xmrigdata, 0)
var cnlitevariant1Data = multiHashing['cryptonight-lite'](xmrigdata, 1)

console.log(hashedData)
console.log(cnvariant1Data)
console.log(cnlitedata)
console.log(cnlitevariant1Data)

assert.deepEqual(hashedData, cnhash)
assert.deepEqual(cnvariant1Data, xmrigcnvariant1hash)
assert.deepEqual(cnlitedata, xmrigcnlitehash)
assert.deepEqual(cnlitevariant1Data, xmrigcnlitevariant1hash)
