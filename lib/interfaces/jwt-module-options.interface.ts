import { ModuleMetadata, Type } from '@nestjs/common/interfaces';
import * as jwt from 'jsonwebtoken';

export enum JwtSecretRequestType {
  SIGN,
  VERIFY
}

export interface JwtModuleOptions {
  signOptions?: jwt.SignOptions;
  secret?: string | Buffer;
  publicKey?: string | Buffer;
  privateKey?: jwt.Secret;
  /**
   * @deprecated
   */
  secretOrPrivateKey?: jwt.Secret;
  secretOrKeyProvider?: (
    requestType: JwtSecretRequestType,
    tokenOrPayload: string | object | Buffer,
    options?: jwt.VerifyOptions | jwt.SignOptions
  ) => jwt.Secret | Promise<jwt.Secret>;
  verifyOptions?: jwt.VerifyOptions;
}

export interface JwtOptionsFactory {
  createJwtOptions(): Promise<JwtModuleOptions> | JwtModuleOptions;
}

export interface JwtModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  useExisting?: Type<JwtOptionsFactory>;
  useClass?: Type<JwtOptionsFactory>;
  useFactory?: (...args: any[]) => Promise<JwtModuleOptions> | JwtModuleOptions;
  inject?: any[];
}

export interface JwtSignOptions extends jwt.SignOptions {
  secret?: string | Buffer;
  privateKey?: string | Buffer;
}

export interface JwtVerifyOptions extends jwt.VerifyOptions {
  secret?: string | Buffer;
  publicKey?: string | Buffer;
}

export type GetSecretKeyResult = string | Buffer | jwt.Secret;
