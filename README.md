# C4ID

A JavaScript module for NodeJS to generate C4 IDs. Written in TypeScript. As described in [SMPTE ST 2114:2017](https://pub.smpte.org/latest/st2114/st2114-2017.pdf), a C4 ID is a 90 character Base58 string representation of a SHA512 hash. This package does not create SHA512 hashes, it simply creates their C4 ID representation.

## Installing / Getting started

  ```shell
  $ npm install --save c4id
  ```

  ```javascript
  import { createHash } from 'node:crypto';
  import C4ID from 'c4id';

  const digest = createHash('sha512').update('alfa').digest();
  const c4 = C4ID.fromSHA512Hash(digest);

  console.log(c4); //c43zYcLni5LF9rR4Lg4B8h3Jp8SBwjcnyyeh4bc6gTPHndKuKdjUWx1kJPYhZxYt3zV6tQXpDs2shPsPYjgG81wZM1
  ```

## Developing

### Built With

This package was built and tested on Node.js 16.20.2. 

The only development dependencies [Typescript](https://www.npmjs.com/package/typescript) and packages needed for testing and linting, i.e. [Mocha](https://mochajs.org) and [ESLint](https://eslint.org), plus plugins for both.

### Setting up Dev

```shell
git clone https://github.com/bradcordeiro/c4id
cd c4id
npm install
```

## Versioning

This package uses [Semantic Versioning](https://semver.org).

## Tests

[SMPTE ST 2114:2017](https://pub.smpte.org/latest/st2114/st2114-2017.pdf) includes test cases in Appendix B, and those test cases
are implemented in this package using [Mocha](https://mochajs.org).

```shell
npm test
```
To run the tests using Mocha.

## Style guide

This package was written using the [Airbnb Style Guide](https://github.com/airbnb/javascript). A .eslintrc file is included in source control, and [ESLint](https://eslint.org) as well as the [Airbnb plugin](https://www.npmjs.com/package/eslint-config-airbnb) are included as development dependencies.

## API Reference

#### Functions

Function | Argument Type | Return Type | Description
------ | ------------- | ----------- |------------
fromSHA512Hash(*sha512Hash*) | UInt8Array | string | Takes a SHA512 hash and returns a C4 ID string.
toSHA512Digest(*c4id*) | string | UInt8Array | Takes a C4 ID and returns a SHA512 hash digest.
fromIds(*c4ids*) | string[] | string | [SMPTE ST 2114:2017](https://pub.smpte.org/latest/st2114/st2114-2017.pdf) describes a method to generate a C4 ID from other C4 IDs (e.g. to generate a single C4 ID from multiple files in the same folder). This function will take an array of C4 IDs and return a single C4 ID from the input, as specified in [SMPTE ST 2114:2017](https://pub.smpte.org/latest/st2114/st2114-2017.pdf).

## Licensing

Released under the [MIT License](https://github.com/bradcordeiro/c4id/blob/main/LICENSE).
