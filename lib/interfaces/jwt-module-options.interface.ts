import * as jwt from 'jsonwebtoken';

export interface JwtModuleOptions {
  signOptions?: jwt.SignOptions;
  secretOrPrivateKey?: jwt.Secret;
  publicKey?: string | Buffer;
  verifyOptions?: jwt.VerifyOptions;
}
