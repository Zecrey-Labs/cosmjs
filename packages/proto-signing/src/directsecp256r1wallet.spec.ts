/* eslint-disable @typescript-eslint/naming-convention */
import { coins } from "@zkkontos/amino";
import { Secp256r1, Secp256r1Signature, sha256 } from "@zkkontos/crypto";
import { fromBase64, fromHex } from "@zkkontos/encoding";

import { DirectSecp256r1Wallet } from "./directsecp256r1wallet";
import { makeAuthInfoBytes, makeSignBytes, makeSignDoc } from "./signing";
import { testVectors } from "./testutils.spec";

describe("DirectSecp256r1Wallet", () => {
  const defaultPrivkey = fromHex("5b44b93366536ca29097ad0327d7f8f2da914ba5ab912249882aea77c5ea4992");
  const defaultAddress = "kontos1wsa0kx979dg7gc2ckjg4t3nwafgc53lujw7pqp";
  const defaultPubkey = fromHex("031eebbfbdc9417ba609c9dff678f6a0427ec264c24436512abc1ffeec30105e0d");

  describe("fromKey", () => {
    it("works", async () => {
      const signer = await DirectSecp256r1Wallet.fromKey(defaultPrivkey);
      expect(signer).toBeTruthy();
    });
  });

  describe("getAccounts", () => {
    it("resolves to a list of accounts", async () => {
      const signer = await DirectSecp256r1Wallet.fromKey(defaultPrivkey);
      const accounts = await signer.getAccounts();
      expect(accounts.length).toEqual(1);
      expect(accounts[0]).toEqual({
        address: defaultAddress,
        algo: "ksecp256r1",
        pubkey: defaultPubkey,
      });
    });
  });

  describe("signDirect", () => {
    it("resolves to valid signature", async () => {
      const { accountNumber, sequence, bodyBytes } = testVectors[1].inputs;
      const wallet = await DirectSecp256r1Wallet.fromKey(defaultPrivkey);
      const accounts = await wallet.getAccounts();
      const pubkey = {
        typeUrl: "/cosmos.crypto.ksecp256r1.PubKey",
        value: accounts[0].pubkey,
      };
      const fee = coins(2000, "ucosm");
      const gasLimit = 200000;
      const chainId = "simd-testing";
      const feePayer = undefined;
      const feeGranter = undefined;
      const signDoc = makeSignDoc(
        fromHex(bodyBytes),
        makeAuthInfoBytes([{ pubkey, sequence }], fee, gasLimit, feeGranter, feePayer),
        chainId,
        accountNumber,
      );
      const signDocBytes = makeSignBytes(signDoc);
      const { signature } = await wallet.signDirect(accounts[0].address, signDoc);
      const valid = await Secp256r1.verifySignature(
        Secp256r1Signature.fromFixedLength(fromBase64(signature.signature)),
        sha256(signDocBytes),
        pubkey.value,
      );
      expect(valid).toEqual(true);
    });
  });
});
