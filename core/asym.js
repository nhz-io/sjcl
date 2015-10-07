/** @fileOverview Asymmetric encryption (base64 centered).
 *
 * @author Ishi Ruy
 */

/** sjcl.codec.base64.fromBits wrapper
 * @param {bitArray} data The data to convert
 * @return {String} Base64 encoded data
 */

var to64 = function (data) {
 return sjcl.codec.base64.fromBits(data);
}

/** sjcl.codec.base64.toBits wrapper
 * @param {String} data Base64 encoded data
 * @return {bitArray} converted binary data
 */

var from64 = function (data) {
  return sjcl.codec.base64.toBits(data);
}

/** sjcl.codec.utf8String.fromBits wrapper
 * @param {bitArray} data The data to convert
 * @return {String} UTF8 String
 */

var toUTF8 = function (data) {
  return pt = sjcl.codec.utf8String.fromBits(data);
}

/** sjcl.codec.utf8String.toBits wrapper
 * @param {String} UTF8 String
 * @return {bitArray} converted binary data
 */

var fromUTF8 = function (data) {
  return sjcl.codec.utf8String.toBits(data);
}

/** Context initializer
 * @return {Object} Context
 */

var initp = function () {
  return { v: 1, iter: 1000, ks: 128, ts: 64, moe: "ccm", adata: [], cipher: "aes" }
}

var tag = function (pub) {
  pub = new sjcl.ecc.elGamal.publicKey(sjcl.ecc.curves.c256, from64(pub));
  return to64(pub.kem().tag);
}

 /** @namespace Asymmetric encryption */

sjcl.asym = {
  to64: to64,

  from64: from64,

  initp: initp,

  tag: tag,

  /** Keypair generator
   * @return {Array} Public, Secret Base64 key strings
   */
  genkeys: function() {
      var pair = sjcl.ecc.elGamal.generateKeys(256);
      var pub = pair.pub.get(), sec = pair.sec.get();
      return [ to64(pub.x.concat(pub.y)), to64(sec) ];
  },

  /** Encryption function
   * @param {String} pub The public key Base64
   * @param {String} pt The data to encrypt.
   * @return {String} Base64 encrypted data
   */
  encrypt: function (pub, pt) {
    var
      p = initp(), rp = initp(),
      pt = fromUTF8(pt), prp, tmp;
    p.iv = rp.iv = sjcl.random.randomWords(4, 0);
    pub = new sjcl.ecc.elGamal.publicKey(sjcl.ecc.curves.c256, from64(pub)),
    tmp = pub.kem();
    pub = tmp.key.slice(0, 4);
    p.kemtag = rp.kemtag = tmp.tag;
    rp.key = pub;
    prp = new sjcl.cipher.aes(pub);
    window.asym = {
      p: p, pt: pt, pub: pub, prp: prp, rp: rp
    }
    return to64(sjcl.mode.ccm.encrypt(prp, pt, p.iv, p.adata, p.ts))
  },


  /** Decryption function
   * @param {String} sec The secret key Base64
   * @param {String} ct The data to decrypt.
   * @return {String} UTF8 decrypted data.
   */
  decrypt: function (sec, ct, tag) {
    iv = sjcl.random.randomWords(4, 0);
    ct = fromUTF8(ct);
    sec = new sjcl.ecc.elGamal.secretKey(
      sjcl.ecc.curves.c256, sjcl.ecc.curves.c256.field.fromBits(from64(sec))
    );
    sec = sec.unkem(from64(tag)).slice(0, 4);
    console.log("SEC", sec);
    console.log("CT", ct);
    prp = new sjcl.cipher.aes(sec);
    console.log("CIPHER", prp);
    res = sjcl.mode.ccm.decrypt(prp, ct, iv);
    //return to64(sjcl.mode.ccm.decrypt(prp, p.ct, p.iv, p.adata, p.ts));
    console.log("RES", res);
    return to64(res);
  }

}

/** Encryption function; shorthand for sjcl.asym.encrypt.
* @param {String} pub The public key Base64
* @param {String} pt The data to encrypt.
* @return {String} Base64 encrypted data
 */
sjcl.encrypt = sjcl.asym.encrypt;

/** Decryption function; shorthand for sjcl.asym.decrypt.
* @param {String} sec The secret key Base64
* @param {String} ct The data to decrypt.
* @return {String} UTF8 decrypted data.
 */
sjcl.decrypt = sjcl.asym.decrypt;

/** Keypair generator shorthand for sjcl.asym.genkeys.
 * @return {Array} Public, Secret Base64 key strings
 */
sjcl.genkeys = sjcl.asym.genkeys;
