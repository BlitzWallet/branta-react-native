import { DestinationType } from '../v2/types.js';

export function getHashZkType(value: string): DestinationType | null {
  const lower = value.toLowerCase();
  if (lower.startsWith('lnbc') || lower.startsWith('lntb') || lower.startsWith('lnbcrt')) return 'bolt11';
  if (lower.startsWith('ark1')) return 'ark_address';
  return null;
}

export async function toNormalizedHash(value: string): Promise<string> {
  const normalized = value.toLowerCase();
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalized));
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}
