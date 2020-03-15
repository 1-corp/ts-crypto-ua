/*jslint plusplus: true, bitwise: true */
const Buffer = require('buffer').Buffer;

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const B64_URL =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=';
const B64_TEST = /[^A-Za-z0-9\+\/\=]/g;
const B64_REPLACE = /[^A-Za-z0-9\+\/]/g;

export const b64_encode = (numbrs, line, safe, pad) => {
  let table;
  const ret = [];
  let b1;
  let b2;
  let b3;
  let e1;
  let e2;
  let e3;
  let e4;
  let i = 0;
  if (typeof line === 'object') {
    safe = line.safe;
    pad = line.pad;
    line = line.line;
  }
  if (safe === true) {
    table = B64_URL;
  } else {
    table = B64;
  }
  while (i < numbrs.length) {
    if (i > 0 && line !== undefined && i % line === 0) {
      ret.push('\n');
    }

    b1 = numbrs[i++];
    b2 = numbrs[i++];
    b3 = numbrs[i++];

    e1 = b1 >> 2;
    e2 = ((b1 & 3) << 4) | (b2 >> 4);
    e3 = ((b2 & 15) << 2) | (b3 >> 6);
    e4 = b3 & 63;

    ret.push(table.charAt(e1));
    ret.push(table.charAt(e2));
    if (b2 !== undefined) ret.push(table.charAt(e3));
    if (b3 !== undefined) ret.push(table.charAt(e4));
  }
  i = numbrs.length % 3;
  if (pad && i === 2) {
    ret.push('=');
  }
  if (pad && i === 1) {
    ret.push('==');
  }
  return ret.join('');
};

export const b64_decode = input => {
  let output;
  let output_len;
  let chr1;
  let chr2;
  let chr3;
  let enc1;
  let enc2;
  let enc3;
  let enc4;
  let i = 0;
  let o = 0;

  if (B64_TEST.exec(input)) {
    throw new Error('invalid b64 input');
  }

  // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
  input = input.replace(B64_REPLACE, '');
  output_len = Math.floor((input.length * 3) / 4);
  output = new Buffer(output_len);

  do {
    enc1 = B64.indexOf(input.charAt(i++));
    enc2 = B64.indexOf(input.charAt(i++));
    enc3 = B64.indexOf(input.charAt(i++));
    enc4 = B64.indexOf(input.charAt(i++));

    chr1 = (enc1 << 2) | (enc2 >> 4);
    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
    chr3 = ((enc3 & 3) << 6) | enc4;

    output[o++] = chr1;
    output[o++] = chr2;
    output[o++] = chr3;
  } while (i < input.length);

  return output;
};
