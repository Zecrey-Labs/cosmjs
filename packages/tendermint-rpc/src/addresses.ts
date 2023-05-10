import {ripemd160, sha256} from "@zkkontos/crypto";
import {toHex} from "@zkkontos/encoding";

export function rawEd25519PubkeyToRawAddress(pubkeyData: Uint8Array): Uint8Array {
  if (pubkeyData.length !== 32) {
    throw new Error(`Invalid Ed25519 pubkey length: ${pubkeyData.length}`);
  }
  return sha256(pubkeyData).slice(0, 20);
}

export function rawBLS12377PubkeyToRawAddress(pubkeyData: Uint8Array): Uint8Array {
  if (pubkeyData.length !== 96) {
    throw new Error(`Invalid BLS12377 pubkey length: ${pubkeyData.length}`);
  }
  return sha256(pubkeyData).slice(0, 20);
}

export function rawSecp256k1PubkeyToRawAddress(pubkeyData: Uint8Array): Uint8Array {
  if (pubkeyData.length !== 33) {
    throw new Error(`Invalid Secp256k1 pubkey length (compressed): ${pubkeyData.length}`);
  }
  return ripemd160(sha256(pubkeyData));
}

/**
 * Returns Tendermint address as bytes.
 *
 * This is for addresses that are derived by the Tendermint keypair (typically Ed25519).
 * Sometimes those addresses are bech32-encoded and contain the term "cons" in the presix
 * ("cosmosvalcons1...").
 *
 * For secp256k1 this assumes we already have a compressed pubkey, which is the default in Cosmos.
 */
export function pubkeyToRawAddress(type: "ed25519" | "secp256k1" | "bls12377", data: Uint8Array): Uint8Array {
  switch (type) {
    case "ed25519":
      return rawEd25519PubkeyToRawAddress(data);
    case "secp256k1":
      return rawSecp256k1PubkeyToRawAddress(data);
    case "bls12377":
      return rawBLS12377PubkeyToRawAddress(data);
    default:
      // Keep this case here to guard against new types being added but not handled
      throw new Error(`Pubkey type ${type} not supported`);
  }
}

/**
 * Returns Tendermint address in uppercase hex format.
 *
 * This is for addresses that are derived by the Tendermint keypair (typically Ed25519).
 * Sometimes those addresses are bech32-encoded and contain the term "cons" in the presix
 * ("cosmosvalcons1...").
 *
 * For secp256k1 this assumes we already have a compressed pubkey, which is the default in Cosmos.
 */
export function pubkeyToAddress(type: "ed25519" | "secp256k1" | "bls12377", data: Uint8Array): string {
  return toHex(pubkeyToRawAddress(type, data)).toUpperCase();
}
