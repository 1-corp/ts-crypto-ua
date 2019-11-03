import { Gost } from '../src/gost89';

describe('Gost', function() {
  describe('#crypt()', function() {
    it('should encrypt multiply blocks', function() {
      const expect_cypher = 'e393a17df2b6de6f2086d8230c277432';

      const ctx = new Gost();
      const key = Buffer.from(
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        'hex'
      );
      const clear = Buffer.from('0001020304050607f1f2f3f4f5f6f7f8', 'hex');
      const out = Buffer.alloc(16);

      ctx.key(key);
      ctx.crypt(clear, out);

      expect(out.toString('hex')).toEqual(expect_cypher);
    });
  });

  describe('#decrypt()', function() {
    it('should decrypt multiply blocks', function() {
      const expect_clear = '0001020304050607f1f2f3f4f5f6f7f8';

      const ctx = new Gost();
      const key = Buffer.from(
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        'hex'
      );
      const cypher = Buffer.from('e393a17df2b6de6f2086d8230c277432', 'hex');
      const out = Buffer.alloc(16);

      ctx.key(key);
      ctx.decrypt(cypher, out);

      expect(out.toString('hex')).toEqual(expect_clear);
    });
  });

  describe('#crypt_cfb()', function() {
    it('should encrypt multiply blocks in CFB mode', function() {
      const expect_c = '2087da2008227235a919d76142e8ce65';

      const ctx = new Gost();
      const iv = Buffer.from('F1F2F3F4F5F6F7F8', 'hex');
      const key = Buffer.from(
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        'hex'
      );
      const clear = Buffer.from('0001020304050607f1f2f3f4f5f6f7f8', 'hex');
      const out = Buffer.alloc(16);

      ctx.key(key);
      ctx.crypt_cfb(iv, clear, out);

      expect(out.toString('hex')).toEqual(expect_c);
    });
  });

  describe('#decrypt_cfb()', function() {
    it('should decrypt multiply blocks in CFB mode', function() {
      const expect_clear = '0001020304050607f1f2f3f4f5f6f7f8';

      const ctext = Buffer.from('2087da2008227235a919d76142e8ce65', 'hex');
      const clear = Buffer.alloc(16);
      const ctx = new Gost();

      const iv = Buffer.from('F1F2F3F4F5F6F7F8', 'hex');
      const key = Buffer.from(
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        'hex'
      );

      ctx.key(key);
      ctx.decrypt_cfb(iv, ctext, clear);

      expect(clear.toString('hex')).toEqual(expect_clear);
    });
  });
});
