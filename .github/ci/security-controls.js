'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const root = '/source';
const forge = require(root + '/lib');
const asn1 = forge.asn1;
const vector = JSON.parse(fs.readFileSync('/source/.github/ci/upstream-vector.json', 'utf8'));
const keys = crypto.generateKeyPairSync('rsa', {modulusLength: 2048, publicExponent: 65537});
const privateKey = forge.pki.privateKeyFromPem(keys.privateKey.export({type:'pkcs1', format:'pem'}));
const publicKey = forge.pki.publicKeyFromPem(keys.publicKey.export({type:'spki', format:'pem'}));
const message = 'bounded forge verification';
const digest = crypto.createHash('sha256').update(message).digest('latin1');
const oid = asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes();
const results = [];
function observe(name, expected, fn, classification) {
  let accepted = false, rejection = null;
  try { accepted = fn(); assert.equal(typeof accepted, 'boolean'); }
  catch (error) {
    if (!(error instanceof Error) || (error.message !== 'Invalid OID encoding.' &&
      !/^(ASN.1 object does not contain a valid|Unknown RSASSA-PKCS1-v1_5)/.test(error.message))) {
      throw error;
    }
    rejection = error.message;
  }
  results.push({name, classification, expected_accepted:expected, accepted, pass:accepted === expected, rejection});
}
// Same ASN.1/PKCS#1 construction as upstream PR1157 tests. All signatures here
// use an ephemeral real test private key; these are malformed-encoding checks,
// not a claim of attacker forgery. No verification bypass flags are supplied.
function signInfo(md, options = {}) {
  const algorithm = [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
    options.oid === undefined ? oid : options.oid)];
  if (!options.absent) algorithm.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL,
    false, options.nullValue === undefined ? '' : options.nullValue));
  if (options.extra) algorithm.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, 'x'));
  const info = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, algorithm),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, md)
  ]);
  let encoded = asn1.toDer(info).getBytes();
  if (options.ber) {
    assert(encoded.charCodeAt(1) < 0x80);
    encoded = '\x30\x80' + encoded.slice(2) + '\x00\x00';
  }
  return forge.pki.rsa.encrypt(encoded, privateKey, 0x01);
}
function verify(options = {}, suppliedDigest = digest) {
  return publicKey.verify(suppliedDigest, signInfo(digest, options));
}
observe('absent-null', true, () => verify({absent:true}), 'compatibility');
observe('empty-null', true, () => verify(), 'compatibility');
observe('wrong-digest', false, () => verify({}, '\x00'.repeat(32)), 'rejection-control');
observe('ber-indefinite-outer', true, () => verify({ber:true}), 'compatibility');
for (const n of [1,8,32]) {
  observe('nonempty-null-' + n, false, () => verify({nullValue:'x'.repeat(n)}), 'malformed-encoding');
  observe('unterminated-oid-80-' + n, false, () => verify({oid:oid + '\x80'.repeat(n)}), 'malformed-encoding');
}
observe('unterminated-oid-81', false, () => verify({oid:oid + '\x81'}), 'malformed-encoding');
observe('nonminimal-oid-arc', false, () => verify({oid:oid[0] + '\x80' + oid.slice(1)}), 'malformed-encoding');
observe('completed-unknown-oid-arc', false, () => verify({oid:oid + '\x00'}), 'rejection-control');
observe('extra-nested-child', false, () => verify({extra:true}), 'malformed-encoding');
observe('native-node-signature', true, () => publicKey.verify(digest,
  crypto.sign('sha256', Buffer.from(message), keys.privateKey).toString('latin1')), 'compatibility');
const pss = forge.pss.create({md:forge.md.sha256.create(),
  mgf:forge.mgf.mgf1.create(forge.md.sha256.create()), saltLength:20});
const md = forge.md.sha256.create(); md.update(message);
observe('pss', true, () => publicKey.verify(digest, privateKey.sign(md, pss), pss), 'compatibility');
const raw = privateKey.sign(digest, 'NONE');
observe('none', true, () => publicKey.verify(digest, raw, 'NONE'), 'compatibility');
observe('none-wrong-digest', false, () => publicKey.verify('\x00'.repeat(32), raw, 'NONE'), 'rejection-control');
// Replay the public-key/signature bytes from the upstream nested-child test
// using default verification. No fixture private exponent is loaded.
const upstreamKey = forge.pki.rsa.setPublicKey(
  new forge.jsbn.BigInteger(vector.N,16), new forge.jsbn.BigInteger(vector.e));
const upstreamDigest = crypto.createHash('sha256').update(vector.message).digest('latin1');
observe('upstream-nested-vector-default', false,
  () => upstreamKey.verify(upstreamDigest, Buffer.from(vector.S,'hex').toString('latin1')),
  'upstream-vector-default-options');
const cert = forge.pki.createCertificate();
cert.publicKey = publicKey; cert.serialNumber = '01';
cert.validity.notBefore = new Date('2026-01-01T00:00:00Z');
cert.validity.notAfter = new Date('2027-01-01T00:00:00Z');
const attrs = [{name:'commonName', value:'synthetic.test.invalid'}];
cert.setSubject(attrs); cert.setIssuer(attrs);
cert.sign(privateKey, forge.md.sha256.create());
observe('x509-normal', true, () => cert.verify(cert), 'caller-compatibility');
const certDigest = cert.md.digest().getBytes();
cert.signature = signInfo(certDigest, {nullValue:'x'});
observe('x509-nonempty-null', false, () => cert.verify(cert), 'caller-malformed-encoding');
cert.signature = signInfo(certDigest, {oid:oid + '\x80'});
observe('x509-unterminated-oid', false, () => cert.verify(cert), 'caller-malformed-encoding');
const csr = forge.pki.createCertificationRequest();
csr.publicKey = publicKey; csr.setSubject(attrs);
csr.sign(privateKey, forge.md.sha256.create());
observe('csr-normal', true, () => csr.verify(), 'caller-compatibility');
const csrDigest = csr.md.digest().getBytes();
csr.signature = signInfo(csrDigest, {nullValue:'x'});
observe('csr-nonempty-null', false, () => csr.verify(), 'caller-malformed-encoding');
csr.signature = signInfo(csrDigest, {oid:oid + '\x80'});
observe('csr-unterminated-oid', false, () => csr.verify(), 'caller-malformed-encoding');
const failed = results.filter(r => !r.pass);
console.log(JSON.stringify({
  node:process.version, openssl:process.versions.openssl, tests:results.length,
  passed:results.length-failed.length, failed:failed.length, observations:results,
  test_keys:'ephemeral-native-generated-2048-bit-RSA-not-retained',
  verification_flags:'DEFAULT except explicit PSS/NONE compatibility cases',
  scope:'BOUNDED_CRYPTOGRAPHIC_ENCODING_COMPATIBILITY_CONTROLS',
  verdict:failed.length ? 'REJECTED' : 'PASS_BOUNDED_CONTROLS'},null,2));
process.exitCode = failed.length ? 1 : 0;
