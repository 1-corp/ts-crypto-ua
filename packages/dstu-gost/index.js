'use strict';

var Gost = require('./src/gost89.js');
var Dstu = require('./src/dstu.js');
var Hash = require('./src/hash.js');
var PRNG = require('./src/prng.js');

var util = require('./src/util.js');
var keywrap = require('./src/keywrap.js');
var compat = require('./src/compat.js');

module.exports = {
    init: Gost.init,
    PRNG: PRNG,
    Hash: Hash,
    gosthash: Hash.gosthash,
    dumb_kdf: util.dumb_kdf,
    pbkdf: util.pbkdf,
    wrap_key: keywrap.wrap,
    unwrap_key: keywrap.unwrap,
    compat: compat,
};
