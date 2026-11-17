// Research arithmetic constructor. Authentic same-source, same-epoch readings
// are a caller premise; a congruence check is not a provenance certificate.
// No full X or carried K enters this constructor.
export function nextStarReadings(r36, v584) {
  if (typeof r36 !== 'bigint' || typeof v584 !== 'bigint'
      || r36 < 0n || r36 >= 36n || v584 < 0n || v584 >= 584n) {
    throw new RangeError('canonical BigInt residues modulo 36 and 584 required');
  }
  const difference = v584 - r36;
  if (difference % 4n !== 0n) {
    throw new RangeError('readings disagree on their shared modulus 4');
  }
  const bit = ((difference / 4n) % 2n + 2n) % 2n;
  const r72 = r36 + 36n * bit;
  const s73 = v584 % 73n;
  return {r72, s73, kMod73: ((r72 - s73) % 73n + 73n) % 73n};
}

// Inverse of the complete frame transfer when the independent old 37-lane
// is retained. Target-only transfer intentionally cannot restore that lane.
export function restoreStarSource(r72, s73, s37) {
  if ([r72,s73,s37].some(v => typeof v !== 'bigint')
      || r72 < 0n || r72 >= 72n || s73 < 0n || s73 >= 73n
      || s37 < 0n || s37 >= 37n) {
    throw new RangeError('canonical BigInt residues modulo 72, 73 and 37 required');
  }
  const octant = ((r72 - s73) % 8n + 8n) % 8n;
  return {r36: r72 % 36n, s37, v584: s73 + 73n * octant};
}
