import { fromHex, toHex } from "@cosmjs/encoding";
import BN from "bn.js";
import elliptic from "elliptic";

import { ExtendedSecp256r1Signature, Secp256r1Signature } from "./secp256r1signature";

const secp256r1 = new elliptic.ec("p256");
const secp256r1N = new BN("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", "hex");

export interface Secp256r1Keypair {
  /** A 32 byte private key */
  readonly pubkey: Uint8Array;
  /**
   * A raw secp256r1 public key.
   *
   * The type itself does not give you any guarantee if this is
   * compressed or uncompressed. If you are unsure where the data
   * is coming from, use `Secp256r1.compressPubkey` or
   * `Secp256r1.uncompressPubkey` (both idempotent) before processing it.
   */
  readonly privkey: Uint8Array;
}

export class Secp256r1 {
  /**
   * Takes a 32 byte private key and returns a privkey/pubkey pair.
   *
   * The resulting pubkey is uncompressed. For the use in Cosmos it should
   * be compressed first using `Secp256r1.compressPubkey`.
   */
  public static async makeKeypair(privkey: Uint8Array): Promise<Secp256r1Keypair> {
    if (privkey.length !== 32) {
      // is this check missing in secp256r1.validatePrivateKey?
      // https://github.com/bitjson/bitcoin-ts/issues/4
      throw new Error("input data is not a valid secp256r1 private key");
    }

    const keypair = secp256r1.keyFromPrivate(privkey);
    if (keypair.validate().result !== true) {
      throw new Error("input data is not a valid secp256r1 private key");
    }

    // range test that is not part of the elliptic implementation
    const privkeyAsBigInteger = new BN(privkey);
    if (privkeyAsBigInteger.gte(secp256r1N)) {
      // not strictly smaller than N
      throw new Error("input data is not a valid secp256r1 private key");
    }

    const out: Secp256r1Keypair = {
      privkey: fromHex(keypair.getPrivate("hex")),
      // encodes uncompressed as
      // - 1-byte prefix "04"
      // - 32-byte x coordinate
      // - 32-byte y coordinate
      pubkey: Uint8Array.from(keypair.getPublic("array")),
    };
    return out;
  }

  /**
   * Creates a signature that is
   * - deterministic (RFC 6979)
   * - lowS signature
   * - DER encoded
   */
  public static async createSignature(
    messageHash: Uint8Array,
    privkey: Uint8Array,
  ): Promise<ExtendedSecp256r1Signature> {
    if (messageHash.length === 0) {
      throw new Error("Message hash must not be empty");
    }
    if (messageHash.length > 32) {
      throw new Error("Message hash length must not exceed 32 bytes");
    }

    const keypair = secp256r1.keyFromPrivate(privkey);
    // the `canonical` option ensures creation of lowS signature representations
    const { r, s, recoveryParam } = keypair.sign(messageHash, { canonical: true });
    if (typeof recoveryParam !== "number") throw new Error("Recovery param missing");
    return new ExtendedSecp256r1Signature(
      Uint8Array.from(r.toArray()),
      Uint8Array.from(s.toArray()),
      recoveryParam,
    );
  }

  public static async verifySignature(
    signature: Secp256r1Signature,
    messageHash: Uint8Array,
    pubkey: Uint8Array,
  ): Promise<boolean> {
    if (messageHash.length === 0) {
      throw new Error("Message hash must not be empty");
    }
    if (messageHash.length > 32) {
      throw new Error("Message hash length must not exceed 32 bytes");
    }

    const keypair = secp256r1.keyFromPublic(pubkey);

    // From https://github.com/indutny/elliptic:
    //
    //     Sign the message's hash (input must be an array, or a hex-string)
    //
    //     Signature MUST be either:
    //     1) DER-encoded signature as hex-string; or
    //     2) DER-encoded signature as buffer; or
    //     3) object with two hex-string properties (r and s); or
    //     4) object with two buffer properties (r and s)
    //
    // Uint8Array is not a Buffer, but elliptic seems to be happy with the interface
    // common to both types. Uint8Array is not an array of ints but the interface is
    // similar
    try {
      return keypair.verify(messageHash, signature.toDer());
    } catch (error) {
      return false;
    }
  }

  public static recoverPubkey(signature: ExtendedSecp256r1Signature, messageHash: Uint8Array): Uint8Array {
    const signatureForElliptic = { r: toHex(signature.r()), s: toHex(signature.s()) };
    const point = secp256r1.recoverPubKey(messageHash, signatureForElliptic, signature.recovery);
    const keypair = secp256r1.keyFromPublic(point);
    return fromHex(keypair.getPublic(false, "hex"));
  }

  /**
   * Takes a compressed or uncompressed pubkey and return a compressed one.
   *
   * This function is idempotent.
   */
  public static compressPubkey(pubkey: Uint8Array): Uint8Array {
    switch (pubkey.length) {
      case 33:
        return pubkey;
      case 65:
        return Uint8Array.from(secp256r1.keyFromPublic(pubkey).getPublic(true, "array"));
      default:
        throw new Error("Invalid pubkey length");
    }
  }

  /**
   * Takes a compressed or uncompressed pubkey and returns an uncompressed one.
   *
   * This function is idempotent.
   */
  public static uncompressPubkey(pubkey: Uint8Array): Uint8Array {
    switch (pubkey.length) {
      case 33:
        return Uint8Array.from(secp256r1.keyFromPublic(pubkey).getPublic(false, "array"));
      case 65:
        return pubkey;
      default:
        throw new Error("Invalid pubkey length");
    }
  }

  public static trimRecoveryByte(signature: Uint8Array): Uint8Array {
    switch (signature.length) {
      case 64:
        return signature;
      case 65:
        return signature.slice(0, 64);
      default:
        throw new Error("Invalid signature length");
    }
  }
}
