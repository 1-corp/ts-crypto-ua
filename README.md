<h1 align="center">Welcome to ts-crypto-ua 👋</h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-0.0.1-blue.svg?cacheSeconds=2592000" />
  <a href="#" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
  <a href="https://twitter.com/warchantua" target="_blank">
    <img alt="Twitter: warchantua" src="https://img.shields.io/twitter/follow/warchantua.svg?style=social" />
  </a>
</p>

Monorepo for crypto primitives used in Ukrainian national crypto.

## Packages

### [@1-corp/dstu-gost](./packages/dstu-gost)

National hash and encryption algorithms.

```sh
npm install @1-corp/dstu-gost
```


### [@1-corp/dstu4145](./packages/dstu4145)

National digital signatures algorithm.

```sh
npm install @1-corp/dstu-dstu4145
```

### [@1-corp/ecp](./packages/ecp)

SDK to work with National "ЕЦП".

```sh
npm install @1-corp/ecp
```

## Run tests

```sh
npm test
```

## Author

The code is heavily based on [dstucrypt's](https://github.com/dstucrypt) work. Migration to Typescript, fixing of small issues, bring everything together and test thoroughly by [@Warchant](https://github.com/warchant).


## 🤝 Contributing

Contributions, issues and feature requests are welcome!<br />Feel free to check [issues page](https://github.com/1-corp/ts-crypto-ua/issues).

