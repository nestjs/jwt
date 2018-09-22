import { Inject, Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { JwtModuleOptions } from './interfaces/jwt-module-options.interface';
import { JWT_MODULE_OPTIONS } from './jwt.constants';

@Injectable()
export class JwtService {
  constructor(
    @Inject(JWT_MODULE_OPTIONS) private readonly options: JwtModuleOptions
  ) {}

  sign(payload: string | Object | Buffer, options?: jwt.SignOptions): string {
    const signOptions = options
      ? {
          ...this.options.signOptions,
          ...options
        }
      : this.options.signOptions;
    return jwt.sign(payload, this.options.secretOrPrivateKey, signOptions);
  }

  verify<T extends object = any>(
    token: string,
    options?: jwt.VerifyOptions
  ): T {
    const verifyOptions = options
      ? {
          ...this.options.verifyOptions,
          ...options
        }
      : this.options.verifyOptions;
    return jwt.verify(
      token,
      this.options.publicKey || (this.options.secretOrPrivateKey as any),
      verifyOptions
    ) as T;
  }

  decode(
    token: string,
    options: jwt.DecodeOptions
  ): null | { [key: string]: any } | string {
    return jwt.decode(token, options);
  }
}
