'use strict';

import {
  Buffer,
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
  pw: Buffer
): Buffer => {
  if (parsed.format === 'IIT') {
    return util.dumb_kdf(pw, 10000);
  }
  if (parsed.format === 'PBES2') {
    return util.pbkdf(pw, parsed.salt, parsed.iters);
  }

  throw new Error('Failed to convert key');
};

export const decode_data = (parsed: ParsedData, pw: Buffer): Buffer => {
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

export const encode_data = (
  raw: Buffer,
  format: string,
  pw: Buffer,
  iv: Buffer,
  salt: Buffer
): EncodedData => {
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

export const compute_hash = (contents: Buffer) => Hash.gosthash(contents);

export const gost_unwrap = (kek: Buffer, inp: Buffer) =>
  keywrap.unwrap(inp, kek);

export const gost_keywrap = (kek: Buffer, inp: Buffer, iv: Buffer) =>
  keywrap.wrap(inp, kek, iv);

export const gost_kdf = (buffer: Buffer) => compute_hash(buffer);

const gost_crypt = (mode: number, inp: Buffer, key: Buffer, iv: Buffer) => {
  const ctx = Gost.init();
  ctx.key(key);
  if (mode) {
    return ctx.decrypt_cfb(iv, inp);
  } else {
    return ctx.crypt_cfb(iv, inp);
  }
};

export const gost_decrypt_cfb = (cypher: Buffer, key: Buffer, iv: Buffer) =>
  gost_crypt(1, cypher, key, iv);

export const gost_encrypt_cfb = (cypher: Buffer, key: Buffer, iv: Buffer) =>
  gost_crypt(0, cypher, key, iv);

export const algos = () => ({
  kdf: gost_kdf,
  keywrap: gost_keywrap,
  keyunwrap: gost_unwrap,
  encrypt: gost_encrypt_cfb,
  decrypt: gost_decrypt_cfb,
  hash: compute_hash,
  storeload: decode_data,
  storesave: encode_data,
});
