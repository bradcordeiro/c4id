import crypto from 'node:crypto';
import Stream from 'node:stream';

const CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split(''); // per SMPTE ST 2114:2017
const BASE = BigInt(CHARSET.length);
const ID_LENGTH = 90; // per SMPTE ST 2114:2017
const BIGZERO = BigInt(0);
const BIG256 = BigInt(256);

const sortDigests = (a: Buffer, b: Buffer) : number => {
  const min = Math.min(a.length, b.length);

  for (let i = min - 1; i >= 0; i -= 1) {
    if (a[i] > b[i]) return 1;
    if (b[i] < a[i]) return -1;
  }

  return 0;
};

export default class C4Hash {
  protected sha512Hash: crypto.Hash;

  constructor() {
    this.sha512Hash = crypto.createHash('sha512');
  }

  protected static digestToId(sha512Hash: Buffer) {
    const digest = sha512Hash.toString('hex');

    let hash = BigInt(`0x${digest}`);
    const id: string[] = Array(ID_LENGTH).fill('1');
    id[0] = 'c';
    id[1] = '4';

    let i = ID_LENGTH - 1;
    while (hash !== BIGZERO) {
      const modulo = Number(hash % BASE);
      hash /= BASE;
      id[i] = CHARSET[modulo];
      i -= 1;
    }

    return id.join('');
  }

  protected static idToDigest(c4id: string) : Buffer {
    const id = c4id.substring(2);

    let result = id
      .split('')
      .reduce((acc, curr) => acc * BASE + BigInt(CHARSET.indexOf(curr)), BIGZERO);

    const c4digest = Buffer.alloc(64);

    for (let i = 63; i >= 0; i -= 1) {
      c4digest[i] = Number(result % BIG256);
      result /= BIG256;
    }

    return c4digest;
  }

  static hash(data: Buffer) : Buffer {
    return new C4Hash().update(data).digest();
  }

  static id(data: Buffer) : string {
    return C4Hash.digestToId(C4Hash.hash(data));
  }

  static generateHashOfHashes(c4ids: (string | Buffer)[]) : string {
    const input = c4ids.map((id) => (typeof id === 'string' ? id : C4Hash.digestToId(id)));

    let digests = Array.from(new Set(input)).sort();

    while (digests.length > 1) {
      let holdingElement: string | undefined;

      if (digests.length % 2 === 1) {
        holdingElement = digests.pop();
      }

      const output: string[] = [];

      for (let i = 0; i < digests.length; i += 2) {
        const pair = digests.slice(i, i + 2).map((d) => C4Hash.idToDigest(d));
        pair.sort(sortDigests);

        const concatted = Buffer.concat(pair);
        const id = C4Hash.id(concatted);

        output.push(id);
      }

      digests = output.slice(0);

      if (holdingElement) {
        digests.push(holdingElement);
        holdingElement = undefined;
      }
    }

    return digests[0];
  }

  reset() {
    this.sha512Hash = crypto.createHash('sha512');
  }

  copy(options?: crypto.HashOptions) : C4Hash {
    const n = new C4Hash();
    n.sha512Hash = this.sha512Hash.copy(options);
    return n;
  }

  update(chunk: crypto.BinaryLike) : C4Hash {
    this.sha512Hash.update(chunk);
    return this;
  }

  digest() : Buffer {
    return this.sha512Hash.digest();
  }

  id() : string {
    return C4Hash.digestToId(this.digest());
  }
}
