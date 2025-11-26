import { createHash } from 'node:crypto';

const CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; // per SMPTE ST 2114:2017
const BIGINT_BASE = BigInt(CHARSET.length);
const ID_LENGTH = 90; // per SMPTE ST 2114:2017

const initializeNewC4IDArray = (): string[] => {
  const id: string[] = Array(ID_LENGTH).fill('1', 2);
  id[0] = 'c';
  id[1] = '4';

  return id;
};

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
    output = (output << 8n) + BigInt(buf[i]);
  }

  return output;
};

const c4IdToBigInt = (c4Id: string): bigint => (
  c4Id
    .substring(2) // omit the leading 'c4' from the C4 ID
    .split('')
    .reduce((acc, curr) => (acc * BIGINT_BASE) + BigInt(getIndexOfCharInCharset(curr)), 0n)
);

/* Sort a pair of UInt8Arrays, works with Array.sort() */
const sortDigests = (a: Uint8Array, b: Uint8Array): number => {
  for (let i = 63; i >= 0; i -= 1) {
    if (a[i] > b[i]) return 1;
    if (b[i] < a[i]) return -1;
  }

  return 0;
};

const sortAndConcatenateDigests = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const sorted = [a, b].sort(sortDigests);
  return Uint8Array.of(...sorted[0], ...sorted[1]);
};

const separateHoldingElement = (c4ids: string[]): [string[], string | undefined] => {
  const remainingElements = [...c4ids];
  let holdingElement: string | undefined;

  if (c4ids.length % 2 === 1) {
    holdingElement = remainingElements.pop();
  }

  return [remainingElements, holdingElement];
};

/**
 * Create a C4 ID from a SHA512 digest.
 */
function fromSHA512Hash(sha512HashDigest: Uint8Array): string {
  let digest = uInt8ArrayToBigInt(sha512HashDigest);
  const id = initializeNewC4IDArray();

  let i = ID_LENGTH - 1;
  while (digest !== 0n && i >= 0) {
    const modulo = Number(digest % BIGINT_BASE);
    id[i] = CHARSET[modulo];
    digest /= BIGINT_BASE;
    i -= 1;
  }

  return id.join('');
}

/**
 * Convert a C4 ID to a SHA512 hash digest
 */
function toSHA512Digest(c4Id: string): Uint8Array {
  let result = c4IdToBigInt(c4Id);
  const sha512Digest = new Uint8Array(64);

  for (let i = 63; i >= 0; i -= 1) {
    sha512Digest[i] = Number(result % 256n);
    result /= 256n;
  }

  return sha512Digest;
}

/**
 * Create a "hash of hashes" from multiple C4 IDs, as described in SMPTE ST 2114:2017
 */
function fromIds(c4ids: string[]) : string {
  let ids = Array.from(new Set(c4ids)).sort();

  while (ids.length > 1) {
    const [elements, holdingElement] = separateHoldingElement(ids);
    const digests = elements.map((d) => toSHA512Digest(d));
    ids = [];

    for (let i = 0; i < digests.length; i += 2) {
      const concatted = sortAndConcatenateDigests(digests[i], digests[i + 1]);
      const digest = createHash('sha512').update(concatted).digest();
      const id = fromSHA512Hash(digest);
      ids.push(id);
    }

    if (holdingElement) {
      ids.push(holdingElement);
    }
  }

  return ids[0];
}

export default {
  fromSHA512Hash,
  toSHA512Digest,
  fromIds,
};
