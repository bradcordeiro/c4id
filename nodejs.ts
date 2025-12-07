import { createHash } from 'node:crypto';
import C4ID, { separateHoldingElement, sortAndConcatenateDigests } from './common';

/**
 * Create a "hash of hashes" from multiple C4 IDs, as described in SMPTE ST 2114:2017.
 */
const fromIds = (c4ids: string[]) : string => {
  let ids = Array.from(new Set(c4ids)).sort();

  while (ids.length > 1) {
    const [elements, holdingElement] = separateHoldingElement(ids);
    const digests = elements.map((d) => C4ID.toSHA512Digest(d));
    ids = [];

    for (let i = 0; i < digests.length; i += 2) {
      const concatted = sortAndConcatenateDigests(digests[i], digests[i + 1]);
      const digest = createHash('sha512').update(concatted).digest();
      const id = C4ID.fromSHA512Hash(digest);
      ids.push(id);
    }

    if (holdingElement) {
      ids.push(holdingElement);
    }
  }

  return ids[0];
};

export default {
  fromSHA512Hash: C4ID.fromSHA512Hash,
  toSHA512Digest: C4ID.toSHA512Digest,
  fromIds,
};
