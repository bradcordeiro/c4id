import { createHash } from 'node:crypto';

const CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split(''); // per SMPTE ST 2114:2017
const BASE = BigInt(CHARSET.length);
const ID_LENGTH = 90; // per SMPTE ST 2114:2017

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
    const modulo = Number(hash % BASE);
    hash /= BASE;
    id[i] = CHARSET[modulo];
    i -= 1;
  }

  return id.join('');
};

/* Function to sort a pair of buffers using Array.sort() */
const sortDigests = (a: Buffer, b: Buffer) : number => {
  const min = a.length > b.length ? b.length : a.length;

  for (let i = min - 1; i >= 0; i -= 1) {
    if (a[i] > b[i]) return 1;
    if (b[i] < a[i]) return -1;
  }

  return 0;
};

const C4ID = {
  fromSHA512Hash(sha512Hash: Buffer): string {
    const hash = bufferToBigInt(sha512Hash);
    return c4IdFromBigInt(hash);
  },

  toSHA512Hash(c4Id: string): Buffer {
    const id = c4Id.substring(2);

    let result = id
      .split('')
      .reduce((acc, curr) => acc * BASE + BigInt(CHARSET.indexOf(curr)), 0n);

    const c4digest = Buffer.alloc(64);

    for (let i = 63; i >= 0; i -= 1) {
      c4digest[i] = Number(result % 256n);
      result /= 256n;
    }

    return c4digest;
  },

  fromIds(c4ids: string[]) : string {
    const unique = Array.from(new Set(c4ids)).sort();
    let digests = Array.from(unique).sort();

    while (digests.length > 1) {
      let holdingElement: string | undefined;

      if (digests.length % 2 === 1) {
        holdingElement = digests.pop();
      }

      const output: string[] = [];

      for (let i = 0; i < digests.length; i += 2) {
        const pair = digests.slice(i, i + 2).map((d) => this.toSHA512Hash(d));
        pair.sort(sortDigests);

        const concatted = Buffer.concat(pair);
        const id = this.fromSHA512Hash(createHash('sha512').update(concatted).digest());

        output.push(id);
      }

      digests = output.slice(0);

      if (holdingElement) {
        digests.push(holdingElement);
        holdingElement = undefined;
      }
    }

    return digests[0];
  },
};

export default C4ID;
