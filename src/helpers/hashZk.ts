import { DestinationType } from "../v2/types.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";

export function getHashZkType(value: string): DestinationType | null {
  const lower = value.toLowerCase();
  if (
    lower.startsWith("lnbc") ||
    lower.startsWith("lntb") ||
    lower.startsWith("lnbcrt")
  )
    return "bolt11";
  if (lower.startsWith("ark1")) return "ark_address";
  return null;
}

export async function toNormalizedHash(value: string): Promise<string> {
  const normalized = value.toLowerCase();
  return bytesToHex(sha256(utf8ToBytes(normalized)));
}
