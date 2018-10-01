const Buffer = require('safe-buffer').Buffer
const multiHashing = require('../build/Release/multihashing')
const assert = require('assert')

var xmrigdata = new Buffer('0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02', 'hex')

var cnfasthash = new Buffer('b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0', 'hex')
var xmrigcnhash = new Buffer('1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f', 'hex')
var xmrigcnvariant1hash = new Buffer('c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122', 'hex')
var xmrigcnlitehash = new Buffer('28a22bad3f93d1408fca472eb5ad1cbe75f21d053c8ce5b3af105a57713e21dd', 'hex')
var xmrigcnlitevariant1hash = new Buffer('87c4e570653eb4c2b42b7a0d546559452dfab573b82ec52f152b7ff98e79446f', 'hex')

var cnsoftshellHashv0 = []
cnsoftshellHashv0.push(new Buffer('546c3f1badd7c1232c7a3b88cdb013f7f611b7bd3d1d2463540fccbd12997982', 'hex'))
cnsoftshellHashv0.push(new Buffer('54b7350dd54e73e533ab4012835eec0e2468b01f432822352fd60e9fef70ba4e', 'hex'))
cnsoftshellHashv0.push(new Buffer('a25c8be1e6b4f2696163a5f6852b6bfdd9eabc442bc8bb992ff8aea89a546f9f', 'hex'))
cnsoftshellHashv0.push(new Buffer('c8c4b871cefd49fb8bc4ecd77c9687ec148eeed2180d0f80b002a9de1f509c18', 'hex'))
cnsoftshellHashv0.push(new Buffer('6eae70222ff2121bff32764cb606a6565f10e2fe87a8467ef547d1d271cbfbbd', 'hex'))
cnsoftshellHashv0.push(new Buffer('c8c4b871cefd49fb8bc4ecd77c9687ec148eeed2180d0f80b002a9de1f509c18', 'hex'))
cnsoftshellHashv0.push(new Buffer('a25c8be1e6b4f2696163a5f6852b6bfdd9eabc442bc8bb992ff8aea89a546f9f', 'hex'))
cnsoftshellHashv0.push(new Buffer('54b7350dd54e73e533ab4012835eec0e2468b01f432822352fd60e9fef70ba4e', 'hex'))
cnsoftshellHashv0.push(new Buffer('546c3f1badd7c1232c7a3b88cdb013f7f611b7bd3d1d2463540fccbd12997982', 'hex'))
cnsoftshellHashv0.push(new Buffer('54b7350dd54e73e533ab4012835eec0e2468b01f432822352fd60e9fef70ba4e', 'hex'))
cnsoftshellHashv0.push(new Buffer('a25c8be1e6b4f2696163a5f6852b6bfdd9eabc442bc8bb992ff8aea89a546f9f', 'hex'))
cnsoftshellHashv0.push(new Buffer('c8c4b871cefd49fb8bc4ecd77c9687ec148eeed2180d0f80b002a9de1f509c18', 'hex'))
cnsoftshellHashv0.push(new Buffer('6eae70222ff2121bff32764cb606a6565f10e2fe87a8467ef547d1d271cbfbbd', 'hex'))
cnsoftshellHashv0.push(new Buffer('c8c4b871cefd49fb8bc4ecd77c9687ec148eeed2180d0f80b002a9de1f509c18', 'hex'))
cnsoftshellHashv0.push(new Buffer('a25c8be1e6b4f2696163a5f6852b6bfdd9eabc442bc8bb992ff8aea89a546f9f', 'hex'))
cnsoftshellHashv0.push(new Buffer('54b7350dd54e73e533ab4012835eec0e2468b01f432822352fd60e9fef70ba4e', 'hex'))
cnsoftshellHashv0.push(new Buffer('546c3f1badd7c1232c7a3b88cdb013f7f611b7bd3d1d2463540fccbd12997982', 'hex'))

var cnsoftshellHashv1 = []
cnsoftshellHashv1.push(new Buffer('29e7831780a0ab930e0fe3b965f30e8a44d9b3f9ad2241d67cfbfea3ed62a64e', 'hex'))
cnsoftshellHashv1.push(new Buffer('702c3eb285452dbfce53c17da2c0d309769194880e8c3d4f0c5787efcf055f2f', 'hex'))
cnsoftshellHashv1.push(new Buffer('91f2255c59ecb66fc9fd2ec76c0f385e79fa18d22802c7d426c312af00ebaecf', 'hex'))
cnsoftshellHashv1.push(new Buffer('c81bd0e073c0a35cb2921c0ddf24fd951808fceff572d459685240dda78939ed', 'hex'))
cnsoftshellHashv1.push(new Buffer('ebd1c981c4fb1c0085b7ab28ec164afa2290f079ad5dcffd017976a19700590f', 'hex'))
cnsoftshellHashv1.push(new Buffer('c81bd0e073c0a35cb2921c0ddf24fd951808fceff572d459685240dda78939ed', 'hex'))
cnsoftshellHashv1.push(new Buffer('91f2255c59ecb66fc9fd2ec76c0f385e79fa18d22802c7d426c312af00ebaecf', 'hex'))
cnsoftshellHashv1.push(new Buffer('702c3eb285452dbfce53c17da2c0d309769194880e8c3d4f0c5787efcf055f2f', 'hex'))
cnsoftshellHashv1.push(new Buffer('29e7831780a0ab930e0fe3b965f30e8a44d9b3f9ad2241d67cfbfea3ed62a64e', 'hex'))
cnsoftshellHashv1.push(new Buffer('702c3eb285452dbfce53c17da2c0d309769194880e8c3d4f0c5787efcf055f2f', 'hex'))
cnsoftshellHashv1.push(new Buffer('91f2255c59ecb66fc9fd2ec76c0f385e79fa18d22802c7d426c312af00ebaecf', 'hex'))
cnsoftshellHashv1.push(new Buffer('c81bd0e073c0a35cb2921c0ddf24fd951808fceff572d459685240dda78939ed', 'hex'))
cnsoftshellHashv1.push(new Buffer('ebd1c981c4fb1c0085b7ab28ec164afa2290f079ad5dcffd017976a19700590f', 'hex'))
cnsoftshellHashv1.push(new Buffer('c81bd0e073c0a35cb2921c0ddf24fd951808fceff572d459685240dda78939ed', 'hex'))
cnsoftshellHashv1.push(new Buffer('91f2255c59ecb66fc9fd2ec76c0f385e79fa18d22802c7d426c312af00ebaecf', 'hex'))
cnsoftshellHashv1.push(new Buffer('702c3eb285452dbfce53c17da2c0d309769194880e8c3d4f0c5787efcf055f2f', 'hex'))
cnsoftshellHashv1.push(new Buffer('29e7831780a0ab930e0fe3b965f30e8a44d9b3f9ad2241d67cfbfea3ed62a64e', 'hex'))

var fastHashData = multiHashing['cryptonight'](xmrigdata, true)
var hashedDatav0 = multiHashing['cryptonight'](xmrigdata)
var cnvariant1Data = multiHashing['cryptonight'](xmrigdata, 1)
var cnlitedata = multiHashing['cryptonight-lite'](xmrigdata, 0)
var cnlitevariant1Data = multiHashing['cryptonight-lite'](xmrigdata, 1)

// Easy fill soft shell data
var cnsoftshellDatav0 = []
for (var i = 0; i <= 8192; i += 512) {
  cnsoftshellDatav0.push({height: i, hash: multiHashing['cryptonight-soft-shell'](xmrigdata, 0, i)})
}

// Easy fill soft shell data
var cnsoftshellDatav1 = []
for (i = 0; i <= 8192; i += 512) {
  cnsoftshellDatav1.push({height: i, hash: multiHashing['cryptonight-soft-shell'](xmrigdata, 1, i)})
}

console.log('')
console.log('[#1] Cryptonight Fast Hash: ', fastHashData.toString('hex'))
console.log('[#2] Cryptonight v0: ', hashedDatav0.toString('hex'))
console.log('[#3] Cryptonight v1: ', cnvariant1Data.toString('hex'))
console.log('[#4] Cryptonight Lite v0: ', cnlitedata.toString('hex'))
console.log('[#5] Cryptonight Lite v1: ', cnlitevariant1Data.toString('hex'))

// Spit out soft shell hashes
var count = 6
console.log('')

for (i = 0; i < cnsoftshellDatav0.length; i++) {
  console.log('[#' + count + '] Cryptonight Soft Shell v0 (' + cnsoftshellDatav0[i].height + '): ', cnsoftshellDatav0[i].hash.toString('hex'))
  count++
}

console.log('')
for (i = 0; i < cnsoftshellDatav1.length; i++) {
  console.log('[#' + count + '] Cryptonight Soft Shell v1 (' + cnsoftshellDatav1[i].height + '): ', cnsoftshellDatav1[i].hash.toString('hex'))
  count++
}

assert.deepEqual(fastHashData, cnfasthash)
assert.deepEqual(hashedDatav0, xmrigcnhash)
assert.deepEqual(cnvariant1Data, xmrigcnvariant1hash)
assert.deepEqual(cnlitedata, xmrigcnlitehash)
assert.deepEqual(cnlitevariant1Data, xmrigcnlitevariant1hash)

for (i = 0; i < cnsoftshellDatav0.length; i++) {
  assert.deepEqual(cnsoftshellDatav0[i].hash, cnsoftshellHashv0[i])
}

for (i = 0; i < cnsoftshellDatav1.length; i++) {
  assert.deepEqual(cnsoftshellDatav1[i].hash, cnsoftshellHashv1[i])
}
