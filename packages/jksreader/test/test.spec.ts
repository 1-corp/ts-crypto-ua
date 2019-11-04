import { parse } from '../src';
import { readFileSync } from 'fs';
import { Buffer } from 'buffer';
import { Cert, JKS, Key } from '../src/parse';

const validJKS = `${__dirname}/data/valid.jks`;

describe('jks', () => {
  let jks: JKS;
  it('valid jks can be parsed', () => {
    const bytes = readFileSync(validJKS);
    const parsed = parse(Buffer.from(bytes));
    if (!parsed) {
      throw new Error('can not parse jks');
    }
    jks = parsed;
    expect(jks).toBeDefined();
    expect(jks.format).toEqual('jks');
    expect(jks.material).toHaveLength(3);

    expect(jks.material[0] instanceof Key).toEqual(true);
    expect((jks.material[0] as Key).name).toEqual('key2');
    expect((jks.material[0] as Key).unknown_certs).toHaveLength(0);
    expect((jks.material[0] as Key).key).not.toHaveLength(0);

    expect(jks.material[1] instanceof Key).toEqual(true);
    expect((jks.material[1] as Key).name).toEqual('key1');
    expect((jks.material[1] as Key).unknown_certs).toHaveLength(0);
    expect((jks.material[1] as Key).key).not.toHaveLength(0);

    expect(jks.material[2] instanceof Cert).toEqual(true);
    expect((jks.material[2] as Cert).type).toEqual('bohdan vanieiev');
  });
});
