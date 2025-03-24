import { ModuleMetadata, Provider, Type } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

export enum JwtSecretRequestType {
  SIGN,
  VERIFY
}

/**
 * @publicApi
 */
export interface JwtModuleOptions {
  global?: boolean;
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

/**
 * @publicApi
 */
export interface JwtOptionsFactory {
  createJwtOptions(): Promise<JwtModuleOptions> | JwtModuleOptions;
}

/**
 * @publicApi
 */
export interface JwtModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  global?: boolean;
  useExisting?: Type<JwtOptionsFactory>;
  useClass?: Type<JwtOptionsFactory>;
  useFactory?: (...args: any[]) => Promise<JwtModuleOptions> | JwtModuleOptions;
  inject?: any[];
  extraProviders?: Provider[];
}

/**
 * @publicApi
 */
export interface JwtSignOptions extends jwt.SignOptions {
  secret?: string | Buffer;
  privateKey?: jwt.Secret;
}

/**
 * @publicApi
 */
export interface JwtVerifyOptions extends jwt.VerifyOptions {
  secret?: string | Buffer;
  publicKey?: string | Buffer;
}

export type GetSecretKeyResult = string | Buffer | jwt.Secret;
