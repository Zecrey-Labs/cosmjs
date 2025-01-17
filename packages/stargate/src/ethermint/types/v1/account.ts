/* eslint-disable */
import {BaseAccount} from "cosmjs-types/cosmos/auth/v1beta1/auth";
import * as _m0 from "protobufjs/minimal";
import { isSet, DeepPartial, Exact } from "../../helpers";
export const protobufPackage = "ethermint.types.v1";
/**
 * EthAccount implements the authtypes.AccountI interface and embeds an
 * authtypes.BaseAccount type. It is compatible with the auth AccountKeeper.
 */
export interface EthAccount {
  /** base_account is an authtypes.BaseAccount */
  baseAccount?: BaseAccount;
  /** code_hash is the hash calculated from the code contents */
  codeHash: string;
}
function createBaseEthAccount(): EthAccount {
  return {
    baseAccount: undefined,
    codeHash: "",
  };
}
export const EthAccount = {
  encode(message: EthAccount, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.baseAccount !== undefined) {
      BaseAccount.encode(message.baseAccount, writer.uint32(10).fork()).ldelim();
    }
    if (message.codeHash !== "") {
      writer.uint32(18).string(message.codeHash);
    }
    return writer;
  },
  decode(input: _m0.Reader | Uint8Array, length?: number): EthAccount {
    const reader = input instanceof _m0.Reader ? input : new _m0.Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseEthAccount();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.baseAccount = BaseAccount.decode(reader, reader.uint32());
          break;
        case 2:
          message.codeHash = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromJSON(object: any): EthAccount {
    return {
      baseAccount: isSet(object.baseAccount) ? BaseAccount.fromJSON(object.baseAccount) : undefined,
      codeHash: isSet(object.codeHash) ? String(object.codeHash) : "",
    };
  },
  toJSON(message: EthAccount): unknown {
    const obj: any = {};
    message.baseAccount !== undefined &&
      (obj.baseAccount = message.baseAccount ? BaseAccount.toJSON(message.baseAccount) : undefined);
    message.codeHash !== undefined && (obj.codeHash = message.codeHash);
    return obj;
  },
  fromPartial<I extends Exact<DeepPartial<EthAccount>, I>>(object: I): EthAccount {
    const message = createBaseEthAccount();
    message.baseAccount =
      object.baseAccount !== undefined && object.baseAccount !== null
        ? BaseAccount.fromPartial(object.baseAccount)
        : undefined;
    message.codeHash = object.codeHash ?? "";
    return message;
  },
};
