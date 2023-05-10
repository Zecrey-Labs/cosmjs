import { Secp256r1, Sha256 } from "@cosmjs/crypto";
import { toBech32 } from "@cosmjs/encoding";

import { rawSecp256r1PubkeyToRawAddress } from "./addresses";
import { encodeSecp256r1Signature } from "./signature";
import { serializeSignDoc, StdSignDoc } from "./signdoc";
import { AccountData, AminoSignResponse, OfflineAminoSigner } from "./signer";

/**
 * A wallet that holds a single secp256r1 keypair.
 *
 * If you want to work with BIP39 mnemonics and multiple accounts, use Secp256r1HdWallet.
 */
export class Secp256r1Wallet implements OfflineAminoSigner {
  /**
   * Creates a Secp256r1Wallet from the given private key
   *
   * @param privkey The private key.
   * @param prefix The bech32 address prefix (human readable part). Defaults to "kontos".
   */
  public static async fromKey(privkey: Uint8Array, prefix = "kontos"): Promise<Secp256r1Wallet> {
    const uncompressed = (await Secp256r1.makeKeypair(privkey)).pubkey;
    return new Secp256r1Wallet(privkey, Secp256r1.compressPubkey(uncompressed), prefix);
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

  public async signAmino(signerAddress: string, signDoc: StdSignDoc): Promise<AminoSignResponse> {
    if (signerAddress !== this.address) {
      throw new Error(`Address ${signerAddress} not found in wallet`);
    }
    const message = new Sha256(serializeSignDoc(signDoc)).digest();
    const signature = await Secp256r1.createSignature(message, this.privkey);
    const signatureBytes = new Uint8Array([...signature.r(32), ...signature.s(32)]);
    return {
      signed: signDoc,
      signature: encodeSecp256r1Signature(this.pubkey, signatureBytes),
    };
  }
}
