import { SBox } from './gost89';

export const Buffer = require('buffer').Buffer;

export interface EncodedData {
  format: string;
  iv: Buffer;
  salt: Buffer;
  iters: number;
  body: Buffer;
  sbox: SBox;
}

export interface ConvertPasswordParsed {
  iters: number;
  format: string;
  salt: Buffer;
}

export interface ParsedData extends ConvertPasswordParsed {
  body: Buffer;
  pad: Buffer;
  iv: Buffer;
}
