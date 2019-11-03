Gost89
======

Gost89 cipher and hash function implementations in TypeScript.

Algos
-----

* DSTU Gost 34311-95 hash function
* DSTU Gost 28147-2009 CFB mode block cipher
* DSTU Gost 28147-2009 ECB mode block cipher
* DSTU Gost 28147 key wrapper as specified by DSTSZI [0]
* PBKDF (Gost-34311 based)
* Dumb KDF (N-iterations of hash)

[0] http://dstszi.kmu.gov.ua/dstszi/control/uk/publish/article?showHidden=1&art_id=90096&cat_id=38837

GOST-DSTU Notice
----------------

This package implements GOST functions, however S-BOX used by default comes
from Ukrainian counterpart standard DSTU as original GOST does not specify
explicitly what table to use.


Examples
--------

All function except Hash.update() accept buffer objects, string or byte arrays.

Hash messages:
```typescript
import {gosthash, Hash} from 'dstu-gost'
const hash = gosthash("LA LA LA SHTIRLITZ KURWA VODKA MATRIOSKA");
// <Buffer 0a 32 7f 3b ce e1 f3 de 0f 40 61 2e c3 ce d0 a3 29 51 b8 b2 16 8e 9a 01 0f 5b 15 46 c0 a9 1d 93>

const hash_ctx = new Hash();
hash_ctx.update("ARBITARY SIZED VODKA");
hash_ctx.update("VODKA VODKA MORE VODKA");
const hash = hash_ctx.finish();
// <Buffer 2c 1e d1 f1 2c 05 13 38 b2 7f 42 5d ea df e0 62 17 e6 9b 2c 19 d4 4a cd 24 ac 8d 5b b7 53 34 3f>

hash_ctx.reset();
hash.update32(buffer_of_32_bytes);

const preallocated = Buffer.alloc(32);
const hash = hash_ctx.finish(preallocated);
// hash === preallocated
```


Encrypt message:

```typescript
import {Gost} from "dstu-gost";
const gost = new Gost();
const clear = Buffer.from('lol', 'binary');
gost.key(Buffer.alloc(32)); // 32 zeroes
const out = Buffer.alloc(32); // preallocate result buffer
gost.crypt(clear, out); // same as const out = gost.crypt(clear);
```

Encrypt messages in CFB mode:

```typescript
import {Gost} from "dstu-gost";
const gost = new Gost();
const out = gost.crypt_cfb(iv, clear);
// out contains encrypted text
```


Properly encrypt message:

```js
const gost = new Gost();
const key = crypto.randomBytes(32);
// set key
gost.key(key); 
const enc = gost.crypt(text, enc);

const iv = crypto.randomBytes(8);
const shared_key = some_diffie_hellman_here(me, you); // see jkurwa
const wrapped_key = wrap_key(key, shared_key, iv);
// send enc and wrapped_key to other party
```
