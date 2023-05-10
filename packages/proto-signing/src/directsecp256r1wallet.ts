import {encodeSecp256r1Signature, rawSecp256r1PubkeyToRawAddress} from "@cosmjs/amino";
import {Secp256r1, sha256} from "@cosmjs/crypto";
import {toBech32} from "@cosmjs/encoding";
import {SignDoc} from "cosmjs-types/cosmos/tx/v1beta1/tx";

import {AccountData, DirectSignResponse, OfflineDirectSigner} from "./signer";
import {makeSignBytes} from "./signing";

/**
 * A wallet that holds a single secp256r1 keypair.
 *
 * If you want to work with BIP39 mnemonics and multiple accounts, use DirectSecp256r1HdWallet.
 */
export class DirectSecp256r1Wallet implements OfflineDirectSigner {
  /**
   * Creates a DirectSecp256r1Wallet from the given private key
   *
   * @param privkey The private key.
   * @param prefix The bech32 address prefix (human readable part). Defaults to "kontos".
   */
  public static async fromKey(privkey: Uint8Array, prefix = "kontos"): Promise<DirectSecp256r1Wallet> {
    const uncompressed = (await Secp256r1.makeKeypair(privkey)).pubkey;
    return new DirectSecp256r1Wallet(privkey, Secp256r1.compressPubkey(uncompressed), prefix);
  }

  private readonly pubkey: Uint8Array;
  private readonly privkey: Uint8Array;
  private readonly prefix: string;

  private constructor(privkey: Uint8Array, pubkey: Uint8Array, prefix: string) {
    this.privkey = privkey;
    this.pubkey = pubkey;
    this.prefix = prefix;
  }

  private get address(): string {
    return toBech32(this.prefix, rawSecp256r1PubkeyToRawAddress(this.pubkey));
  }

  public async getAccounts(): Promise<readonly AccountData[]> {
    return [
      {
        algo: "ksecp256r1",
        address: this.address,
        pubkey: this.pubkey,
      },
    ];
  }

  public async signDirect(address: string, signDoc: SignDoc): Promise<DirectSignResponse> {
    const signBytes = makeSignBytes(signDoc);
    if (address !== this.address) {
      throw new Error(`Address ${address} not found in wallet`);
    }
    const hashedMessage = sha256(signBytes);
    const signature = await Secp256r1.createSignature(hashedMessage, this.privkey);
    const signatureBytes = new Uint8Array([...signature.r(32), ...signature.s(32)]);
    const stdSignature = encodeSecp256r1Signature(this.pubkey, signatureBytes);
    return {
      signed: signDoc,
      signature: stdSignature,
    };
  }
}
