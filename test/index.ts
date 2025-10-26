/* eslint-env mocha */
import { createHash } from 'node:crypto';
import assert from 'node:assert';
import C4ID from '../lib/C4Hash.js';

const INPUTS = [
  'alfa',
  'bravo',
  'charlie',
  'delta',
  'echo',
  'foxtrot',
  'golf',
  'hotel',
  'india',
];

const EXPECTED = [
  'c43zYcLni5LF9rR4Lg4B8h3Jp8SBwjcnyyeh4bc6gTPHndKuKdjUWx1kJPYhZxYt3zV6tQXpDs2shPsPYjgG81wZM1',
  'c42jd8KUQG9DKppN1qt5aWS3PAmdPmNutXyVTb8H123FcuU3shPxpUXsVdcouSALZ4PaDvMYzQSMYCWkb6rop9zhDa',
  'c44erLietE8C1iKmQ3y4ENqA9g82Exdkoxox3KEHops2ux5MTsuMjfbFRvUPsPdi9Pxc3C2MRvLxWT8eFw5XKbRQGw',
  'c42Sv2Wi2Qo8AKbJKnUP6YTSdz8pt9aDaf2Ltx44HF1UDdXANM8Ltk6qEzpncvmVbw6FZxgBumw9Eo2jtGyaQ5gDSC',
  'c41bviGCyTM2stoMYVTVKgBkfC6SitoLRFinp77BcmN9awdaeC9cxPy4zyFQBhmTvRzChawbECK1KBRnw3KnagA5be',
  'c427CsZdfUAHyQBS3hxDFrL9NqgKeRuKkuSkxuYTm26XG7AKAWCjViDuMhHaMmQBkvuHnsxojetbQU1DdxHjzyQw8r',
  'c41yLiwAPdsjiBAAw8AFwQGG3cAWnNbDio21NtHE8yD1Fh5irRE4FsccZvm1WdJ4FNHtR1kt5kev7wERsgYomaQbfs',
  'c44nNyaFuVbt5MCfo2PYWHpwMkBpYTbt14C6TuoLCYH5RLvAFLngER3nqHfXC2GuttcoDxGBi3pY1j3pUF2W3rZD8N',
  'c41nJ6CvPN7m7UkUA3oS2yjXYNSZ7WayxEQXWPae6wFkWwW8WChQWTu61bSeuCERu78BDK1LUEny1qHZnye3oU7DtY',
];

describe('C4Hash', () => {
  describe('hash', () => {
    it('correctly encodes test strings', () => {
      const inputHashes = INPUTS.map((i) => createHash('sha512').update(i).digest());

      inputHashes.forEach((hash, i) => {
        const h = C4ID.fromSHA512Hash(hash);
        assert.strictEqual(h, EXPECTED[i], `${i}: ${EXPECTED[i]} !== ${h}`);
      });
    });

    it('correctly converts an ID to a SHA512 Hash', () => {
      const inputHashes = INPUTS.map((str) => createHash('sha512').update(str).digest());
      const outputSHA512s = EXPECTED.map((id) => C4ID.toSHA512Hash(id));

      for (let i = 0; i < inputHashes.length; i += 1) {
        assert.strictEqual(Buffer.compare(outputSHA512s[i], inputHashes[i]), 0, `${i}: ${outputSHA512s[i]} !== ${inputHashes[i]}`);
      }
    });

    it('correctly encodes a digest of digests', () => {
      const expected = 'c435RzTWWsjWD1Fi7dxS3idJ7vFgPVR96oE95RfDDT5ue7hRSPENePDjPDJdnV46g7emDzWK8LzJUjGESMG5qzuXqq';
      const hashOfHashes = C4ID.fromIds(EXPECTED);

      assert.strictEqual(hashOfHashes, expected);
    });
  });
});
