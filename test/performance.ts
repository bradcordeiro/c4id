import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import C4ID from '../index';

/* eslint-disable no-console */

const inputs: Uint8Array[] = Array(10000);
const mezz: string[] = Array(10000);

for (let i = 0; i < inputs.length; i += 1) {
  inputs[i] = createHash('sha512').update(Math.random().toString()).digest();
  mezz[i] = C4ID.fromSHA512Hash(inputs[i]);
}

performance.measure('fromIds');

performance.mark('Filter Uniques with Set Start');
C4ID.fromIds(mezz);
performance.mark('Filter Uniques with Set End');

console.log(performance.measure('processTime', 'Filter Uniques with Set Start', 'Filter Uniques with Set End'));
