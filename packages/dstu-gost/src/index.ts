'use strict';

import { Gost } from './gost89';
import { Hash } from './hash';
import { dumb_kdf, pbkdf } from './util';
import { unwrap_key, wrap_key } from './keywrap';
import {
  algos,
  compute_hash,
  convert_password,
  decode_data,
  gost_decrypt_cfb,
  gost_encrypt_cfb,
  gost_kdf,
  gost_keywrap,
  gost_unwrap,
} from './compat';
import { PRNG } from './prng';

module.exports = {
  init: () => {
    return new Gost();
  },
  PRNG,
  Hash,
  gosthash: Hash.gosthash,
  dumb_kdf,
  pbkdf,
  wrap_key,
  unwrap_key,
  compat: {
    algos,
    decode_data,
    convert_password,
    compute_hash,
    gost_kdf,
    gost_unwrap,
    gost_keywrap,
    gost_decrypt_cfb,
    gost_encrypt_cfb,
  },
};
