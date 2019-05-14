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
  ) => jwt.Secret;
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
