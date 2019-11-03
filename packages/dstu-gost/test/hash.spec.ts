import { Hash } from '../src/hash';

describe('Hash', function() {
  describe('#gosthash()', function() {
    it('should hash padded value 1', function() {
      const input1 = Buffer.from('12345678901234567890123456789011', 'binary');
      const expect_ret1 =
        '7686f3f4b113aadc97bca9ea054f41821f0676c5c28ffb987e41797a568e1ed4';
      const ret1 = Hash.gosthash(input1);
      expect(ret1.toString('hex')).toEqual(expect_ret1);
    });

    it('should hash padded value 2', function() {
      const input2 = Buffer.from(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'hex'
      );
      const expect_ret2 =
        '811cb06a8ee423182d9cc9d281f783908f4cfbaf47a68be8415d3499674a3063';

      const ret2 = Hash.gosthash(input2);
      expect(ret2.toString('hex')).toEqual(expect_ret2);
    });

    it('should hash short values', function() {
      const expect_ret =
        '34d4da2c04e9c1ceb933282069c864617d94ed7cc5c0a9840c0c1a99629df637';
      const input = Buffer.from('123123', 'binary');
      const ret = Hash.gosthash(input);
      expect(ret.toString('hex')).toEqual(expect_ret);
    });

    it('should hash splitted short chunks', function() {
      const expect_ret =
        '34d4da2c04e9c1ceb933282069c864617d94ed7cc5c0a9840c0c1a99629df637';
      const ctx = new Hash();
      ctx.update(Buffer.from('123', 'binary'));
      ctx.update(Buffer.from('123', 'binary'));
      const ret = Buffer.alloc(32);
      ctx.finish(ret);
      expect(ret.toString('hex')).toEqual(expect_ret);
    });

    it('should hash long chunks', function() {
      const expect_ret =
        'e9312d13d0e0d39aa4a00c77dcfb661883dd0ed8218af48a146168fc60f014dc';
      const input =
        'IGNORE THIS FILE. This file does nothing, contains no useful data, and might go away in future releases.  Do not depend on this file or its contents.';
      const ret = Hash.gosthash(Buffer.from(input, 'binary'));
      expect(ret.toString('hex')).toEqual(expect_ret);
    });
  });
});
