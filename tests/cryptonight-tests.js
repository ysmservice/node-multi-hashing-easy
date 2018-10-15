const Buffer = require('safe-buffer').Buffer
const multiHashing = require('../build/Release/multihashing')
const assert = require('assert')

var xmrigdata = new Buffer('0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02', 'hex')

var cnfasthash = new Buffer('b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0', 'hex')
var xmrigcnvariant0hash = new Buffer('1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f', 'hex')
var xmrigcnvariant1hash = new Buffer('c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122', 'hex')
var xmrigcnvariant2hash = new Buffer('871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578', 'hex')

var xmrigcnlitevariant0hash = new Buffer('28a22bad3f93d1408fca472eb5ad1cbe75f21d053c8ce5b3af105a57713e21dd', 'hex')
var xmrigcnlitevariant1hash = new Buffer('87c4e570653eb4c2b42b7a0d546559452dfab573b82ec52f152b7ff98e79446f', 'hex')
var xmrigcnlitevariant2hash = new Buffer('b7e78fab22eb19cb8c9c3afe034fb53390321511bab6ab4915cd538a630c3c62', 'hex')

var fastHashData = multiHashing['cryptonight'](xmrigdata, true)
var cnvariant0Data = multiHashing['cryptonight'](xmrigdata)
var cnvariant1Data = multiHashing['cryptonight'](xmrigdata, 1)
var cnvariant2Data = multiHashing['cryptonight'](xmrigdata, 2)
var cnlitevariant0Data = multiHashing['cryptonight-lite'](xmrigdata, 0)
var cnlitevariant1Data = multiHashing['cryptonight-lite'](xmrigdata, 1)
var cnlitevariant2Data = multiHashing['cryptonight-lite'](xmrigdata, 2)

console.log('')
console.log('[#1] Cryptonight Fast Hash: ', fastHashData.toString('hex'))
console.log('')
console.log('[#2] Cryptonight v0: ', cnvariant0Data.toString('hex'))
console.log('[#3] Cryptonight v1: ', cnvariant1Data.toString('hex'))
console.log('[#4] Cryptonight v2: ', cnvariant2Data.toString('hex'))
console.log('')
console.log('[#5] Cryptonight Lite v0: ', cnlitevariant0Data.toString('hex'))
console.log('[#6] Cryptonight Lite v1: ', cnlitevariant1Data.toString('hex'))
console.log('[#7] Cryptonight Lite v2: ', cnlitevariant2Data.toString('hex'))

assert.deepEqual(fastHashData, cnfasthash)
assert.deepEqual(cnvariant0Data, xmrigcnvariant0hash)
assert.deepEqual(cnvariant1Data, xmrigcnvariant1hash)
assert.deepEqual(cnvariant2Data, xmrigcnvariant2hash)

assert.deepEqual(cnlitevariant0Data, xmrigcnlitevariant0hash)
assert.deepEqual(cnlitevariant1Data, xmrigcnlitevariant1hash)
assert.deepEqual(cnlitevariant2Data, xmrigcnlitevariant2hash)
