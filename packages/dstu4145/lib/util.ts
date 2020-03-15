import { Field } from './field';

const addZero = (u8:Uint8Array, reorder: boolean) => {
  let ret = [];
  let i;

  // if (u8.toBuffer !== undefined) {
  //   u8 = u8.toBuffer();
  // }

  if (!reorder) {
    ret.push(0);
  }
  for (i = 0; i < u8.length; i++) {
    ret.push(u8[i]);
  }

  if (reorder) {
    ret.push(0);
    ret = ret.reverse();
  }
  return ret;
};

const invert = (u8: Uint8Array) => {
  /*
   * Invert should mask number of "unsed" bits from input.
   * Hoever this bits shold be zeroes and it's safe to
   * ignore them.
   *  mask = 0xFF >>> unused;
   *  */
  let i;

  let cr;
  const ret = [];
  for (i = u8.length - 1; i >= 0; i--) {
    cr = u8[i];
    cr =
      (cr >> 7) |
      ((cr >> 5) & 2) |
      ((cr >> 3) & 4) |
      ((cr >> 1) & 8) |
      ((cr << 1) & 16) |
      ((cr << 3) & 32) |
      ((cr << 5) & 64) |
      ((cr << 7) & 128);
    ret.push(cr);
  }

  return ret;
};

const is_hex = (inp: string) => {
  try {
    Buffer.from(inp, 'hex');
    return true;
  } catch (e) {
    return false;
  }
};

const BIG_BE = inp => Field.from_u8(inp);

const BIG_LE = inp =>
  Field.from_u8(Array.prototype.slice.call(inp, 0).reverse());

/*
 * Construct big number from inverted bit string.
 * This is different from LE as not bits should be
 * inverted as well as bytes.
 */
const BIG_INVERT = inp => addZero(invert(inp));

const maybeHex = (inp, pad) => {
  let tmp;
  let ret;
  if (typeof inp === 'number') {
    ret = [0, inp];
  }

  if (typeof inp === 'string') {
    tmp = inp.replace(/ /g, '');
    if (is_hex(tmp)) {
      return Field.from_hex(tmp, pad);
    }
  }

  if (!ret) {
    ret = inp;
  }

  if (pad) {
    if (!ret.push) {
      ret = Array.prototype.slice.call(inp, 0);
    }
    while (pad--) {
      ret.push(0);
    }
  }

  return new Uint32Array(ret);
};

const strFromUtf8 = ab =>
  decodeURIComponent(escape(String.fromCharCode.apply(null, ab)));

module.exports = {
  add_zero: addZero,
  is_hex,
  invert,
  BIG_BE,
  BIG_LE,
  BIG_INVERT,
  maybeHex,
  strFromUtf8,
};
