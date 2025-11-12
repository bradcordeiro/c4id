import { createHash } from 'node:crypto';

const CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split(''); // per SMPTE ST 2114:2017
const BIGINT_BASE = BigInt(CHARSET.length);
const ID_LENGTH = 90; // per SMPTE ST 2114:2017

const getIndexOfCharInCharset = (char: string): number => {
  const x = char.charCodeAt(0);
  let difference = 0;

  /* Converts a Unicode value to an index in the CHARSET */

  // '1' to '9'
  if (x >= 49 && x <= 57) difference = 49;
  // 'A' to 'H'
  else if (x >= 65 && x <= 72) difference = 56;
  // 'J' to 'N'
  else if (x >= 74 && x <= 78) difference = 57;
  // 'P' to 'Z'
  else if (x >= 80 && x <= 90) difference = 58;
  // 'a' to 'k'
  else if (x >= 97 && x <= 107) difference = 64;
  // 'm' to 'z'
  else if (x >= 109 && x <= 122) difference = 65;

  return x - difference;
};

/* Converts a UInt8Array of arbitrary size to a BigInt */
const uInt8ArrayToBigInt = (buf: Uint8Array): bigint => {
  let output = 0n;

  for (let i = 0; i < buf.length; i += 1) {
    output = (output << 8n) + BigInt(buf[i]); /* eslint-disable-line no-bitwise */
  }

  return output;
};

/* Sort a pair of UInt8Arrays, works with Array.sort() */
const sortDigests = (a: Uint8Array, b: Uint8Array): number => {
  for (let i = 63; i >= 0; i -= 1) {
    if (a[i] > b[i]) return 1;
    if (b[i] < a[i]) return -1;
  }

  return 0;
};

/* Sort and hash a pair of UInt8Arrays */
const hashPair = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const pair = [a, b].sort(sortDigests);

  const concatted = Uint8Array.of(...pair[0], ...pair[1]);
  return createHash('sha512').update(concatted).digest();
};

const C4ID = {
  /* Create a C4 ID from a SHA512 digest UInt8Array */
  fromSHA512Hash(sha512Hash: Uint8Array): string {
    let hash = uInt8ArrayToBigInt(sha512Hash);

    const id: string[] = Array(ID_LENGTH).fill('1');
    id[0] = 'c';
    id[1] = '4';

    let i = ID_LENGTH - 1;
    while (hash !== 0n && i >= 0) {
      const modulo = Number(hash % BIGINT_BASE);
      hash /= BIGINT_BASE;
      id[i] = CHARSET[modulo];
      i -= 1;
    }

    return id.join('');
  },

  /* Revert a C4 ID to a SHA512 hash digest UInt8Array */
  toSHA512Digest(c4Id: string): Uint8Array {
    const id = c4Id.substring(2).split(''); // omit the leading 'c4' from the C4 ID

    let result = id.reduce((acc, curr) => (acc * BIGINT_BASE) + BigInt(getIndexOfCharInCharset(curr)), 0n);
    const sha512Digest = new Uint8Array(64);

    for (let i = 63; i >= 0; i -= 1) {
      sha512Digest[i] = Number(result % 256n);
      result /= 256n;
    }

    return sha512Digest;
  },

  /* Create a "hash of hashes" from multiple C4 IDs, as described in SMPTE ST 2114:2017 */
  fromIds(c4ids: string[]) : string {
    let digests = Array.from(new Set(c4ids)).sort();

    while (digests.length > 1) {
      let holdingElement: string | undefined;

      if (digests.length % 2 === 1) {
        holdingElement = digests.pop();
      }

      const hashes = digests.map((d) => this.toSHA512Digest(d));
      digests = [];

      for (let i = 0; i < hashes.length; i += 2) {
        const concatted = hashPair(hashes[i], hashes[i + 1]);
        const id = this.fromSHA512Hash(concatted);
        digests.push(id);
      }

      if (holdingElement) {
        digests.push(holdingElement);
      }
    }

    return digests[0];
  },
};

export default C4ID;
