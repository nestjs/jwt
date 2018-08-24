import { ModuleMetadata, Type } from '@nestjs/common/interfaces';
import * as jwt from 'jsonwebtoken';

export interface JwtModuleOptions {
  signOptions?: jwt.SignOptions;
  secretOrPrivateKey?: jwt.Secret;
  publicKey?: string | Buffer;
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
