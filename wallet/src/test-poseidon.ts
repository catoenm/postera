/**
 * Simple test script for Poseidon hashing.
 * Import this in your app or run via browser console.
 */

// Ensure polyfills are loaded
import './polyfills';

import { initPoseidon, noteCommitment, deriveNullifier, poseidonHash, DOMAIN_NOTE_COMMITMENT } from './poseidon';

export async function testPoseidon(): Promise<void> {
  console.log('Initializing Poseidon...');
  await initPoseidon();
  console.log('Poseidon initialized!');

  // Test basic hash
  const testInput = 12345n;
  const hash = poseidonHash(DOMAIN_NOTE_COMMITMENT, [testInput]);
  console.log('Test hash:', hash.toString(16));

  // Test note commitment
  const value = 1000000000n; // 1 PSTR
  const pkHash = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
  const randomness = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321n;

  const commitment = noteCommitment(value, pkHash, randomness);
  console.log('Note commitment:', commitment.toString(16));

  // Test nullifier derivation
  const nullifierKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaan;
  const position = 5n;

  const nullifier = deriveNullifier(nullifierKey, commitment, position);
  console.log('Nullifier:', nullifier.toString(16));

  console.log('All Poseidon tests passed!');
}

// Auto-run if loaded directly
if (typeof window !== 'undefined') {
  (window as unknown as Record<string, unknown>).testPoseidon = testPoseidon;
  console.log('Run testPoseidon() in console to test Poseidon hashing');
}
