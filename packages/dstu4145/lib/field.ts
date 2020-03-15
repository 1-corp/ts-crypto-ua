const Buffer = require('buffer').Buffer;
const _pure = require('./gf2m.js');
let impl = _pure;

export class Field {
  private bytes: Uint8Array;
  private length: number;
  private curve: any;
  private _is_field: boolean;
  private mod_bits: any;
  private mod_words: number;

  constructor(in_value: null, fmt: string | undefined, curve) {
    if (curve === undefined || curve.mod_words === undefined) {
      throw new Error('pass curve to field constructor');
    }

    if (in_value === null) {
      this.bytes = new Uint32Array(curve.mod_words);
      this.length = curve.mod_words;
    } else {
      this.setValue(in_value, fmt, curve.mod_words);
    }

    this._is_field = true;
    this.curve = curve;
    this.mod_bits = curve.mod_bits;
    this.mod_words = curve.mod_words;
  }

  toString(raw: boolean) {
    let txt = '';
    let chr;
    let skip = true;
    const _bytes = this.bytes;

    for (let i = _bytes.length - 1; i >= 0; i--) {
      chr = _bytes[i].toString(16);
      if (skip && _bytes[i] === 0) {
        continue;
      }
      while (chr.length < 8 && !skip) chr = `0${chr}`;
      txt += chr;
      skip = false;
    }

    if (raw) {
      return txt;
    }

    return `<Field ${txt}>`;
  }

  mod_mul({ bytes }: Field) {
    let s = this.curve.mod_tmp;
    impl.mul(this.bytes, bytes, s);
    s = impl.mod(s, this.mod_bits).subarray(0, this.mod_words);
    return new Field(s, undefined, this.curve);
  }

  mod_sqr() {
    return this.mod_mul(this);
  }

  mod() {
    const rbuf = impl.mod(this.bytes, this.mod_bits);
    return new Field(rbuf, undefined, this.curve);
  }

  addM({ bytes }: Field, _from: undefined) {
    const that_b = bytes;
    const that_len = that_b.length;
    const this_b = _from || this.bytes;
    let to_b = this.bytes;
    const iter_len = Math.max((to_b || _from).length, that_len);
    let i;

    if (to_b.length < that_len) {
      to_b = new Uint32Array(this.mod_words);
    }

    for (i = 0; i < iter_len; i++) {
      to_b[i] = this_b[i] ^ (that_b[i] || 0);
    }

    this.bytes = to_b;
    this.length = to_b.length;
  }

  add(that: Field) {
    const ret = new Field(null, undefined, this.curve);
    ret.addM(that, this.bytes);
    return ret;
  }

  is_zero() {
    const blen = this.length;
    let idx;
    for (idx = 0; idx < blen; idx++) {
      if (this.bytes[idx] !== 0) return false;
    }

    return true;
  }

  equals({ length, bytes }: Field) {
    let blen = this.length;
    let olen = length;
    let idx;
    const bb = this.bytes;
    let diff = 0;
    const ob = bytes;

    while (ob[olen - 1] === 0) olen--;

    while (bb[blen - 1] === 0) blen--;

    if (olen !== blen) {
      return false;
    }

    for (idx = 0; idx < blen; idx++) {
      diff |= this.bytes[idx] ^ ob[idx];
    }

    return diff === 0;
  }

  less({ length, bytes }: Field) {
    let blen = this.length;
    let olen = length;
    const bb = this.bytes;
    const ob = bytes;

    while (ob[olen - 1] === 0) olen--;

    while (bb[blen - 1] === 0) blen--;

    if (olen > blen) {
      return true;
    }

    return bb[blen] < ob[olen];
  }

  bitLength() {
    return _pure.blength(this.bytes);
  }

  testBit(n: number) {
    const testWord = Math.floor(n / 32);
    const testFit = n % 32;
    const word = this.bytes[testWord];
    const mask = 1 << testFit;

    if (word === undefined) return true;

    return (word & mask) !== 0;
  }

  clone() {
    return new Field(new Uint32Array(this.bytes), undefined, this.curve);
  }

  clearBit(n: number) {
    const testWord = Math.floor(n / 32);
    const testBit = n % 32;
    let word = this.bytes[testWord];
    const mask = 1 << testBit;

    if (word === undefined) return this;

    word ^= word & mask;

    const ret = this.clone();
    ret.bytes[testWord] = word;
    return ret;
  }

  setBit(n: number) {
    const testWord = Math.floor(n / 32);
    const testBit = n % 32;
    const word = this.bytes[testWord];
    const mask = 1 << testBit;

    if (word === undefined) return this;

    const ret = this.clone();
    ret.bytes[testWord] |= mask;
    return ret;
  }

  shiftRight(bits: number) {
    if (bits === 0) return this.clone();

    return new Field(
      _pure.shiftRight(this.bytes, bits, false),
      undefined,
      this.curve
    );
  }

  shiftRightM(bits: number) {
    if (bits === 0) return;
    _pure.shiftRight(this.bytes, bits, true);
  }

  buf8() {
    const ret = new Uint8Array(this.bytes.length * 4);
    const l = ret.length;
    let idx;

    for (idx = 0; idx < this.bytes.length; idx++) {
      ret[l - idx * 4 - 1] = this.bytes[idx] & 0xff;
      ret[l - idx * 4 - 2] = (this.bytes[idx] >>> 8) & 0xff;
      ret[l - idx * 4 - 3] = (this.bytes[idx] >>> 16) & 0xff;
      ret[l - idx * 4 - 4] = (this.bytes[idx] >>> 24) & 0xff;
    }

    return ret;
  }

  le() {
    const bytes = Math.ceil(this.curve.m / 8);
    const data = this.buf8();
    return new Buffer(data.reverse()).slice(0, bytes);
  }

  truncate_buf8() {
    const ret = this.buf8();

    const start = ret.length - this.curve.order.bitLength() / 8;

    if (start < 0) {
      return ret;
    }

    return ret.subarray(start);
  }

  is_negative() {
    return false;
  }

  trace() {
    const bitmL = this.curve.m;
    let idx;
    let rv = this;

    for (idx = 1; idx <= bitmL - 1; idx++) {
      rv = rv.mod_mul(rv);
      rv.addM(this);
    }

    return rv.bytes[0] & 1;
  }

  setValue(in_value: Uint32Array, fmt: string | undefined, mod_words: number) {
    if (in_value !== null && in_value._is_field) throw new Error('wtf');

    if (fmt === undefined || fmt === 'buf32') {
      this.bytes = in_value;
      this.length = in_value.length;
      return;
    }

    if (fmt === 'hex') {
      this.bytes = fromHex(in_value, mod_words);
      this.length = this.bytes.length;
      return;
    }

    if (fmt === 'bn') {
      in_value = in_value.toArray();
      fmt = 'buf8';
    }

    if (fmt === 'buf8') {
      this.bytes = fromU8(in_value, mod_words);
      this.length = this.bytes.length;
    }
  }

  invert(inplace, _reuse_buf) {
    const a = impl.mod(this.bytes, this.mod_bits);
    const p = this.curve.calc_modulus(this.mod_bits);
    impl.inv(a, p, a);

    return new Field(a, undefined, this.curve);
  }
}

const HEX = '0123456789ABCDEF';

export const fromHex = (inValue: string, maxSize: number) => {
  let idx;
  let chr;
  let code;
  let vidx = 0;
  let bpos = 0;
  let size = Math.ceil(inValue.length / 8);
  size = Math.max(size, maxSize || size);
  const value = new Uint32Array(size);
  for (idx = inValue.length - 1; idx >= 0; idx--) {
    chr = inValue.charAt(idx).toUpperCase();
    code = HEX.indexOf(chr);
    bpos = bpos % 8;
    if (code < 0) {
      throw new Error(`Wrong input at ${idx}`);
    }
    value[vidx] |= code << (bpos * 4);
    if (bpos === 7) vidx++;
    bpos++;
  }
  return value;
};

export const fromU8 = (inValue: Uint8Array, maxSize: number): Uint32Array => {
  let vidx = 0;
  let bpos = 0;
  let size = Math.ceil(inValue.length / 4);
  size = Math.max(size, maxSize || size);
  const value = new Uint32Array(size);
  let idx;
  let code;

  for (idx = inValue.length - 1; idx >= 0; idx--) {
    code = inValue[idx];
    bpos = bpos % 4;

    if (code < 0) {
      code = 256 + code;
    }
    value[vidx] |= code << (bpos * 8);

    if (bpos === 3) vidx++;
    bpos++;
  }

  return value;
};

module.exports = Field;
module.exports.set_impl = _impl => {
  impl = _impl;
};
