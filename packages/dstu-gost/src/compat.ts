'use strict';

import {
  Buffer,
  Bytes,
  ParsedData,
  EncodedData,
  ConvertPasswordParsed,
} from './types';

const keywrap = require('./keywrap.js');
const util = require('./util.js');
const Gost = require('./gost89.js');
const Hash = require('./hash.js');
const dstu = require('./dstu.js');

export const convert_password = (
  parsed: ConvertPasswordParsed,
  pw: Bytes
): Buffer => {
  if (parsed.format === 'IIT') {
    return util.dumb_kdf(pw, 10000);
  }
  if (parsed.format === 'PBES2') {
    return util.pbkdf(pw, parsed.salt, parsed.iters);
  }

  throw new Error('Failed to convert key');
};

export const decode_data = (parsed: ParsedData, pw: Bytes): Buffer => {
  let bkey;

  const ctx = Gost.init();
  let buf, obuf;
  bkey = convert_password(parsed, pw);
  ctx.key(bkey);

  if (parsed.format === 'IIT') {
    buf = Buffer.concat([parsed.body, parsed.pad]);
    obuf = Buffer.alloc(buf.length);
    ctx.decrypt(buf, obuf);
    return obuf.slice(0, parsed.body.length);
  }
  if (parsed.format === 'PBES2') {
    buf = parsed.body;
    obuf = Buffer.alloc(buf.length);
    ctx.decrypt_cfb(parsed.iv, buf, obuf);
    return obuf;
  }

  throw new Error('Failed to decode data');
};

export const encode_data = function(
  raw: Bytes,
  format: string,
  pw: Bytes,
  iv: Bytes,
  salt: Bytes
): EncodedData {
  const ctx = Gost.init();
  if (format === 'PBES2') {
    const iters = 10000;
    const sbox = dstu.packSbox(dstu.defaultSbox);
    const bkey = convert_password({ iters, salt, format }, pw);
    ctx.key(bkey);
    const obuf = Buffer.alloc(raw.length);
    ctx.crypt_cfb(iv, raw, obuf);
    return { format, iv, salt, iters, body: obuf, sbox };
  }

  throw new Error('failed to encode data');
};

export const compute_hash = function(contents: Bytes) {
  return Hash.gosthash(contents);
};

export const gost_unwrap = function(kek: Bytes, inp: Bytes) {
  return keywrap.unwrap(inp, kek);
};

export const gost_keywrap = function(kek: Bytes, inp: Bytes, iv: Bytes) {
  return keywrap.wrap(inp, kek, iv);
};

export const gost_kdf = function(buffer: Bytes) {
  return compute_hash(buffer);
};

export const gost_crypt = function(
  mode: number,
  inp: Bytes,
  key: Bytes,
  iv: Bytes
) {
  const ctx = Gost.init();
  ctx.key(key);
  if (mode) {
    return ctx.decrypt_cfb(iv, inp);
  } else {
    return ctx.crypt_cfb(iv, inp);
  }
};

export const gost_decrypt_cfb = function(cypher: Bytes, key: Bytes, iv: Bytes) {
  return gost_crypt(1, cypher, key, iv);
};

export const gost_encrypt_cfb = function(cypher: Bytes, key: Bytes, iv: Bytes) {
  return gost_crypt(0, cypher, key, iv);
};

module.exports.decode_data = decode_data;
module.exports.convert_password = convert_password;
module.exports.compute_hash = compute_hash;
module.exports.gost_kdf = gost_kdf;
module.exports.gost_unwrap = gost_unwrap;
module.exports.gost_keywrap = gost_keywrap;
module.exports.gost_decrypt_cfb = gost_decrypt_cfb;
module.exports.gost_encrypt_cfb = gost_encrypt_cfb;
module.exports.algos = function() {
  return {
    kdf: gost_kdf,
    keywrap: gost_keywrap,
    keyunwrap: gost_unwrap,
    encrypt: gost_encrypt_cfb,
    decrypt: gost_decrypt_cfb,
    hash: compute_hash,
    storeload: decode_data,
    storesave: encode_data,
  };
};
