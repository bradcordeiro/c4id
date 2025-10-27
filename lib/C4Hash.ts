import { createHash } from 'node:crypto';

const CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split(''); // per SMPTE ST 2114:2017
const BIGINT_BASE = BigInt(CHARSET.length);
const ID_LENGTH = 90; // per SMPTE ST 2114:2017

const getIndexOfCharInCharset = (char: string): bigint => {
  const i = char.charCodeAt(0);
  let difference = 0;

  // '1' to '9'
  if (i >= 49 && i <= 57) difference = 49;
  // 'A' to 'H'
  else if (i >= 65 && i <= 72) difference = 56;
  // 'J' to 'N'
  else if (i >= 74 && i <= 78) difference = 57;
  // 'P' to 'Z'
  else if (i >= 80 && i <= 90) difference = 58;
  // 'a' to 'k'
  else if (i >= 97 && i <= 107) difference = 64;
  // 'm' to 'z'
  else if (i >= 109 && i <= 122) difference = 65;

  return BigInt(i - difference);
};

/* Converts a buffer of arbitrary size to a BigInt */
const bufferToBigInt = (buf: Buffer) : bigint => {
  let output = 0n;

  for (let i = 0; i < buf.length; i += 1) {
    output = (output << 8n) + BigInt(buf[i]); /* eslint-disable-line no-bitwise */
  }

  return output;
};

/* Creates a C4 ID from a BigInt representation of a SHA512 digest (64 byte integer) */
const c4IdFromBigInt = (n: bigint): string => {
  let hash = n;
  const id: string[] = Array(ID_LENGTH).fill('1');
  id[0] = 'c';
  id[1] = '4';

  let i = ID_LENGTH - 1;
  while (hash !== 0n) {
    const modulo = Number(hash % BIGINT_BASE);
    hash /= BIGINT_BASE;
    id[i] = CHARSET[modulo];
    i -= 1;
  }

  return id.join('');
};

/* Function to sort a pair of buffers using Array.sort() */
const sortDigests = (a: Buffer, b: Buffer) : number => {
  for (let i = 63; i >= 0; i -= 1) {
    if (a[i] > b[i]) return 1;
    if (b[i] < a[i]) return -1;
  }

  return 0;
};

const hashPair = (a: Buffer, b: Buffer) : Buffer => {
  const pair = [a, b].sort(sortDigests);

  const concatted = Buffer.concat(pair);
  return createHash('sha512').update(concatted).digest();
};

const C4ID = {
  /* Create a C4 ID from a SHA512 digest buffer */
  fromSHA512Hash(sha512Hash: Buffer): string {
    const hash = bufferToBigInt(sha512Hash);
    return c4IdFromBigInt(hash);
  },

  /* Revert a C4 ID to a SHA512 hash digest buffer */
  toSHA512Digest(c4Id: string): Buffer {
    const id = c4Id.substring(2).split('');
    let result = id.reduce((acc, curr) => acc * BIGINT_BASE + getIndexOfCharInCharset(curr), 0n);
    const sha512Digest = Buffer.alloc(64);

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
