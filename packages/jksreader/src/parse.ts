export interface JksStream {
  buf: Buffer;
  pos: number;
}

export class Cert {
  constructor(readonly type: string, readonly data: Buffer) {}
}

export class Key {
  constructor(
    readonly key: Buffer,
    readonly certs: Buffer[],
    readonly name: string,
    readonly unknown_certs: Buffer[]
  ) {}
}

export type KeyOrCert = Key | Cert;

export interface JKS {
  format: string;
  material: KeyOrCert[];
}

const reader = (buf: Buffer, pos?: number): JksStream => ({
  buf,
  pos: pos || 0,
});

const U32 = (inst: JksStream): number => {
  const ret = inst.buf.readUInt32BE(inst.pos);
  inst.pos += 4;
  return ret;
};
const U16 = (inst: JksStream): number => {
  const ret = inst.buf.readUInt16BE(inst.pos);
  inst.pos += 2;
  return ret;
};
const BIN = (inst: JksStream, len: number): Buffer => {
  const ret = inst.buf.slice(inst.pos, inst.pos + len);
  inst.pos += len;
  return ret;
};
const STR = (inst: JksStream, len: number): string => BIN(inst, len).toString();

const readCert = (_jks: JksStream): Cert => {
  const type = STR(_jks, U16(_jks));
  const data = BIN(_jks, U32(_jks));
  return new Cert(type, data);
};

const readKey = (_jks: JksStream): Key => {
  const name = STR(_jks, U16(_jks));
  U32(_jks); // skip timestamp high
  U32(_jks); // skip timestamp low
  const key = BIN(_jks, U32(_jks)).slice(0x18); // drop header

  const chain = U32(_jks);
  const certs = [];
  const unknown_certs = [];
  for (let j = 0; j < chain; j++) {
    const cert: Cert = readCert(_jks);
    if (cert.type === 'X.509') {
      certs.push(cert.data);
    } else {
      unknown_certs.push(cert.data);
    }
  }
  return new Key(key, certs, name, unknown_certs);
};

const MAGIC_JKS = 0xfeedfeed;

export const parse = (jks: Buffer): JKS | null => {
  const _jks = reader(jks);
  const magic = U32(_jks);
  if (magic !== MAGIC_JKS) {
    return null;
  }
  const version = U32(_jks);
  if (version !== 2) {
    return null;
  }
  const entries = U32(_jks);
  const material = [];
  for (let i = 0; i < entries; i++) {
    const tag = U32(_jks);
    if (tag === 1) {
      material.push(readKey(_jks));
    }
    if (tag === 2) {
      material.push(readCert(_jks));
    }
  }
  return {
    format: 'jks',
    material,
  };
};
