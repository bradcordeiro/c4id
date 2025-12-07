/* eslint-env browser */
import C4ID, { separateHoldingElement, sortAndConcatenateDigests } from './common';

/**
 * Create a "hash of hashes" from multiple C4 IDs, as described in SMPTE ST 2114:2017.
 */
const fromIds = async (c4ids: string[]) : Promise<string> => {
  let ids = Array.from(new Set(c4ids)).sort();

  while (ids.length > 1) {
    const [elements, holdingElement] = separateHoldingElement(ids);
    const digests = elements.map((d) => C4ID.toSHA512Digest(d));
    ids = [];

    const hashPromises: Promise<ArrayBuffer>[] = [];

    for (let i = 0; i < digests.length; i += 2) {
      const concatted = sortAndConcatenateDigests(digests[i], digests[i + 1]);
      const digest = crypto.subtle.digest('SHA-512', Buffer.from(concatted));
      hashPromises.push(digest);
    }

    const resolved = await Promise.all(hashPromises); /* eslint-disable-line no-await-in-loop */
    ids = resolved.map((r) => C4ID.fromSHA512Hash(new Uint8Array(r)));

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
