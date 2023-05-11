import {encodeSecp256r1Signature, rawSecp256r1PubkeyToRawAddress} from "@zkkontos/amino";
import {keccak256, Secp256r1, sha256} from "@zkkontos/crypto";
import {fromHex, toBech32, toHex} from "@zkkontos/encoding";
import {SignDoc} from "cosmjs-types/cosmos/tx/v1beta1/tx";

import {AccountData, DirectSignResponse, OfflineDirectSigner} from "./signer";
import {makeSignBytes} from "./signing";
import {ethers} from "ethers";

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

  /**
   * Creates a DirectSecp256r1Wallet from the given private key
   *
   * @param pubKey The compressed public key
   * @param name
   * @param prefix The bech32 address prefix (human readable part). Defaults to "kontos".
   */
  public static async fromPubKeyForQuery(
    pubKey: Uint8Array,
    name = "",
    prefix = "kontos",
  ): Promise<DirectSecp256r1Wallet> {
    return new DirectSecp256r1Wallet(undefined, pubKey, prefix, name);
  }

  public readonly pubkey: Uint8Array;
  public readonly privkey: Uint8Array | undefined;
  public readonly prefix: string;
  public readonly name: string;
  public readonly kontosAddress: string;
  public readonly nameAddress: string;

  private constructor(privkey: Uint8Array | undefined, pubkey: Uint8Array, prefix: string, name = "") {
    this.privkey = privkey;
    this.pubkey = pubkey;
    this.prefix = prefix;
    this.name = name;
    this.nameAddress = DirectSecp256r1Wallet.nameToAddress(this.name);
    this.kontosAddress = this.address;
  }

  public static nameToAddress(name: string): string {
    const nameBytes = fromHex(ethers.utils.defaultAbiCoder.encode(["string"], [name]).slice(2));
    const addressBytes = keccak256(nameBytes).slice(12);
    return "0x" + toHex(addressBytes);
  }

  private get address(): string {
    if (this.name === "") {
      return toBech32(this.prefix, rawSecp256r1PubkeyToRawAddress(this.pubkey));
    } else {
      const address = fromHex(DirectSecp256r1Wallet.nameToAddress(this.name).slice(2));
      return toBech32(this.prefix, address);
    }
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
    if (this.privkey === undefined) {
      throw new Error(`PrivateKey ${this.privkey} not found in wallet`);
    }
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
