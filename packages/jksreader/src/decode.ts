import { Buffer } from 'buffer';
const sha1 = require('js-sha1');

const encode_utf16 = (str: string) => {
  const buf = Buffer.alloc(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    buf[i * 2] = (code & 0xff00) >> 8;
    buf[i * 2 + 1] = code & 0xff;
  }
  return buf;
};

export const decode = (buf: Buffer, password: string) => {
  let i;
  const pw = encode_utf16(password);
  const iv = buf.slice(0, 20);
  const data = buf.slice(20, buf.length - 20);
  const check = buf.slice(buf.length - 20);

  const open = Buffer.alloc(data.length);
  let pos = 0;

  let cur = iv;

  while (pos < data.length) {
    const hash = sha1.create();
    hash.update(pw);
    hash.update(cur);
    cur = hash.digest();

    for (i = 0; i < cur.length; i++) {
      open[pos] = data[pos] ^ cur[i];
      pos++;
    }
  }

  const toCheck = sha1.create();
  toCheck.update(pw);
  toCheck.update(open);
  const digest = toCheck.digest();

  let match = 0;
  for (i = 0; i < check.length; i++) {
    match = digest[i] ^ check[i] || match;
  }

  return match === 0 ? open : null;
};
