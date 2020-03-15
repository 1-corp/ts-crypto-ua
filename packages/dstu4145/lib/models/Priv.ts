/*jslint plusplus: true */
const jk = require('../curve.js');
const bn = require('bn.js');
const util = require('../util.js');
const random = require('../rand.js');
const pem = require('../util/pem');
const b64_encode = require('../util/base64.js').b64_encode;
const dstszi2010 = require('../spec/dstszi2010.js');
const pbes2 = require('../spec/pbes.js');
const keystore = require('../spec/keystore.js');
const ks = require('../spec/keystore.js');
const DstuPrivkey = ks.DstuPrivkey;
const Pub = require('./Pub.js');
const Field = require('../field.js');
const Buffer = require('buffer').Buffer;

const gost_salt = ukm =>
  dstszi2010.SharedInfo.encode(
    {
      keyInfo: {
        algorithm: 'Gost28147-cfb-wrap',
        parameters: null
      },
      entityInfo: ukm || undefined,
      suppPubInfo: new Buffer('\x00\x00\x01\x00')
    },
    'der'
  );

const detect_format = inp => {
  if (util.is_hex(inp) === true) {
    return 'hex';
  }
  throw new Error('Unknown privkey format');
};

const attr_parse = attr => {
  const ahash = {};
  let i;
  let aob;
  let priv1_d;
  let dstu;
  let curve;
  for (i = 0; i < attr.length; i++) {
    aob = attr[i];
    if (aob.id !== undefined) {
      ahash[aob.id] = aob.value[0].value;
    }
  }
  if (!ahash.DSTU_4145_KEY_BITS) {
    return undefined;
  }

  if (ahash.DSTU_4145_CURVE === undefined) {
    return undefined;
  }

  priv1_d = ahash.DSTU_4145_KEY_BITS.data;
  dstu = ahash.DSTU_4145_CURVE;
  if (priv1_d === undefined || priv1_d.length === 0) {
    return undefined;
  }

  curve = jk.Curve.resolve(dstu.curve);

  return curve.pkey(util.BIG_INVERT(priv1_d), 'buf8');
};

function curve_params(p) {
  return new jk.Curve({
    m: p.p.param_m,
    ks: jk.Curve.ks_parse(p.p.ks),
    a: [p.param_a],
    b: util.BIG_LE(p.param_b),
    order: util.BIG_BE(p.order.toArray()),
    kofactor: [4 >> p.param_a],
    base: util.BIG_LE(p.bp)
  });
}

const from_asn1 = (data, return_store) => {
  let key0;
  let key1;
  let priv;
  let curve;

  priv = DstuPrivkey.decode(data, 'der');
  const params = priv.priv0.p.p;
  curve = params.type === 'id' ? jk.std_curve(params.value) : curve_params(params.value);
  key0 = curve.pkey(util.BIG_LE(priv.param_d), 'buf32');
  key0.sbox = priv.priv0.p.sbox;
  if (return_store !== true) {
    return key0;
  }

  key1 = attr_parse(priv.attr);
  return {
    keys: key1 ? [key0, key1] : [key0],
    format: 'privkeys'
  };
};

const short_sign = ({ s, r }, raw) => {
  let tmp_s;
  let tmp_r;
  let mlen;
  let sbuf;
  let idx;
  let tmp;
  tmp_s = s.truncate_buf8();
  tmp_r = r.truncate_buf8();
  mlen = Math.max(tmp_s.length, tmp_r.length);
  sbuf = new Buffer(2 + mlen * 2);
  sbuf.writeUInt8(4, 0);
  sbuf.writeUInt8(mlen * 2, 1);

  for (idx = 0; idx < mlen; idx++) {
    tmp = tmp_r[mlen - idx - 1];
    sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2);
  }

  for (idx = 0; idx < mlen; idx++) {
    tmp = tmp_s[mlen - idx - 1];
    sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2 + mlen);
  }
  if (raw) {
    return sbuf.slice(2);
  }

  return sbuf;
};

const sign_serialise = (data, fmt) => {
  if (fmt === 'short' || fmt === 'le') {
    return short_sign(data, fmt === 'le');
  }

  throw new Error(`Unkown signature format ${fmt}`);
};

class Priv {
  private type = 'Priv';
  private algorithm = 'Dstu4145le';
  private d: any;
  private curve: any;

  constructor(p_curve, param_d) {
    this.d = param_d._is_field ? param_d : new Field(param_d, 'bn', p_curve);
    this.curve = p_curve;
  }

  help_sign(hash_v, rand_e) {
    let eG;
    let r;
    let s;
    let big_d;
    let big_rand_e;
    let big_order;

    eG = this.curve.base.mul(rand_e);
    if (eG.x.is_zero()) {
      return null;
    }
    r = hash_v.mod_mul(eG.x);

    r = this.curve.truncate(r);
    if (r.is_zero()) {
      return null;
    }

    r = new bn.BN(r.buf8(), 8);
    big_d = new bn.BN(this.d.buf8(), 8);
    big_rand_e = new bn.BN(rand_e.buf8(), 8);
    big_order = new bn.BN(this.curve.order.buf8(), 8);
    s = big_d.mul(r).mod(big_order);
    s = s.add(big_rand_e).mod(big_order);

    return {
      s: new Field(s.toArray(), 'buf8', this.curve),
      r: new Field(r.toArray(), 'buf8', this.curve)
    };
  }

  sign(hash_buf, fmt) {
    let rand_e;
    let ret;
    let hash_v;

    if (Buffer.isBuffer(hash_buf)) {
      hash_v = new Field(util.add_zero(hash_buf, true), 'buf8', this.curve);
    } else {
      throw new Error('not a buffer');
    }

    if (hash_v.is_zero()) {
      throw new Error('Pass non zero value');
    }

    while (true) {
      rand_e = this.curve.rand();

      ret = this.help_sign(hash_v, rand_e);
      if (ret !== null) {
        break;
      }
    }

    ret.hash = hash_v;
    if (fmt === undefined) {
      return ret;
    }
    return sign_serialise(ret, fmt);
  }

  decrypt(data, pubkey, { ukm, wcek, iv }, algo) {
    if (pubkey.pubkey) {
      pubkey = pubkey.pubkey;
    }
    const kek = this.sharedKey(pubkey, ukm, algo.kdf);
    const cek = algo.keyunwrap(kek, wcek);
    return algo.decrypt(data, cek, iv);
  }

  encrypt(data, { pubkey }, algo) {
    const crypto = global.crypto;

    const cek = random(new Buffer(32));
    const ukm = random(new Buffer(64));
    const iv = random(new Buffer(8));

    const kek = this.sharedKey(pubkey, ukm, algo.kdf);
    const wcek = algo.keywrap(kek, cek, iv);
    const ctext = algo.encrypt(data, cek, iv);
    return {
      iv,
      wcek,
      data: ctext,
      ukm
    };
  }

  pub_match(pub_key) {
    let check_key = null;
    if (pub_key.type === 'Pub') {
      return pub_key.point.equals(this.pub().point);
    }
    if (pub_key._is_field) {
      check_key = pub_key;
    }
    if (Buffer.isBuffer(pub_key)) {
      check_key = new Field(pub_key, 'buf8', this.curve);
    }
    if (check_key === null) {
      throw new Error('Unknow pubkey format');
    }

    return check_key.equals(this.pub_compress());
  }

  pub_compress() {
    if (this._pub === undefined) {
      this._pub = this.pub();
    }

    if (this._pub_cmp === undefined) {
      this._pub_cmp = this._pub.point.compress();
    }

    return this._pub_cmp;
  }

  pub() {
    return new Pub(this.curve, this.curve.base.mul(this.d).negate());
  }

  /*
        Diffie-Hellman key exchange proto and DSTSZI key wrapping algo
        Implementation note:

            ephemeral keys are not supported, so curves SHOULD match.
    */
  derive(pubkey) {
    let pointQ;
    let pointZ;
    let bufZZ;
    let cut;
    if (pubkey.type === 'Pub') {
      pointQ = pubkey.point;
    } else {
      pointQ = this.curve.point(pubkey);
    }
    pointZ = pointQ.mul(this.d.mod_mul(this.curve.kofactor));
    bufZZ = new Buffer(pointZ.x.buf8(), 'binary');
    cut = bufZZ.length - Math.ceil(this.curve.m / 8);
    return bufZZ.slice(cut);
  }

  /*
        * Computes key for symmetric cypher for two given parties.
        * kdf function should be passed in arguments.
        *
        * pubkey can be either
        *  - {x, y} hash,
        *  - Pub model instance with point on same curve or
        *  - Bignum with compressed representation of key
        *
        * ukm (salt) should be either 32 bytes buffer or null.
        * */
  sharedKey(pubkey, ukm, kdf) {
    let zz;
    let counter;
    let salt;
    let kek_input;

    zz = this.derive(pubkey);
    if (zz[0] === 0) {
      zz = zz.slice(1);
    }
    counter = new Buffer('\x00\x00\x00\x01');
    salt = gost_salt(ukm);

    kek_input = new Buffer(zz.length + counter.length + salt.length);
    zz.copy(kek_input);
    counter.copy(kek_input, zz.length);
    salt.copy(kek_input, zz.length + counter.length);

    return kdf(kek_input);
  }

  as_pem() {
    return `-----BEGIN PRIVATE KEY-----\n${b64_encode(this.as_asn1(), { line: 16, pad: true })}\n-----END PRIVATE KEY-----`;
  }

  as_asn1() {
    const key = this.as_struct();
    return DstuPrivkey.encode(key, 'der');
  }

  as_struct() {
    const key = {
      version: 0,
      priv0: {
        id: 'DSTU_4145_LE',
        p: {
          p: {
            type: 'params',
            value: this.curve.as_struct()
          },
          sbox: dstszi2010.DEFAULT_SBOX_COMPRESSED
        }
      },
      param_d: Array.prototype.slice.call(this.d.buf8()).reverse(),
      attr: []
    };
    return key;
  }
}

Priv.prototype.to_pem = Priv.prototype.as_pem;

Priv.prototype.to_asn1 = Priv.prototype.as_asn1;

const from_pem = (data, return_store) => from_asn1(pem.maybe_pem(data), return_store);

const from_protected = (data, password, algo) => {
  let store;
  if (password && (!algo || !algo.storeload)) {
    throw new Error('Cant decode protected file without algo');
  }

  data = pem.maybe_pem(data);
  if (password) {
    try {
      store = pbes2.enc_parse(data);
    } catch (ignore) {}
    try {
      store = pbes2.enc_parse2(data);
    } catch (ignore) {}
    try {
      store = keystore.enc_parse(data);
    } catch (ignore) {}

    if (!store) {
      throw new Error('Cant parse store with either PBES2 or proprietaty format');
    }

    data = algo.storeload(store, password);
  }
  return Priv.from_asn1(data, true);
};

module.exports = Priv;
module.exports.detect_format = detect_format;
module.exports.from_asn1 = from_asn1;
module.exports.from_pem = from_pem;
module.exports.from_protected = from_protected;
module.exports.sign_serialise = sign_serialise;
