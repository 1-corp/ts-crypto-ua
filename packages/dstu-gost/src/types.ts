import { SBox } from './gost89';

export const Buffer = require('buffer').Buffer;

export type Bytes = Buffer | string | Uint8Array;

export interface EncodedData {
  format: string;
  iv: Uint8Array;
  salt: Uint8Array;
  iters: number;
  body: Buffer;
  sbox: SBox;
}

export interface ConvertPasswordParsed {
  iters: number;
  format: string;
  salt: Uint8Array;
}

export interface ParsedData extends ConvertPasswordParsed{
  body: Buffer;
  pad: Buffer;
  iv: Buffer;
}
