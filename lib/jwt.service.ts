import { Inject, Injectable, Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import {
  JwtModuleOptions,
  JwtSecretRequestType
} from './interfaces/jwt-module-options.interface';
import { JWT_MODULE_OPTIONS } from './jwt.constants';

@Injectable()
export class JwtService {
  private readonly logger = new Logger('JwtService');

  constructor(
    @Inject(JWT_MODULE_OPTIONS) private readonly options: JwtModuleOptions
  ) {}

  sign(payload: string | Buffer | object, options?: jwt.SignOptions): string {
    const signOptions = this.mergeJwtOptions(
      options,
      'signOptions'
    ) as jwt.SignOptions;
    const secret = this.getSecretKey(
      payload,
      options,
      'privateKey',
      JwtSecretRequestType.SIGN
    );

    return jwt.sign(payload, secret, signOptions);
  }

  signAsync(
    payload: string | Buffer | object,
    options?: jwt.SignOptions
  ): Promise<string> {
    const signOptions = this.mergeJwtOptions(
      options,
      'signOptions'
    ) as jwt.SignOptions;
    const secret = this.getSecretKey(
      payload,
      options,
      'privateKey',
      JwtSecretRequestType.SIGN
    );

    return new Promise((resolve, reject) =>
      jwt.sign(payload, secret, signOptions, (err, encoded) =>
        err ? reject(err) : resolve(encoded)
      )
    );
  }

  verify<T extends object = any>(
    token: string,
    options?: jwt.VerifyOptions
  ): T {
    const verifyOptions = this.mergeJwtOptions(options, 'verifyOptions');
    const secret = this.getSecretKey(
      token,
      options,
      'publicKey',
      JwtSecretRequestType.VERIFY
    );

    return jwt.verify(token, secret.toString(), verifyOptions) as T;
  }

  verifyAsync<T extends object = any>(
    token: string,
    options?: jwt.VerifyOptions
  ): Promise<T> {
    const verifyOptions = this.mergeJwtOptions(options, 'verifyOptions');
    const secret = this.getSecretKey(
      token,
      options,
      'publicKey',
      JwtSecretRequestType.VERIFY
    );

    return new Promise((resolve, reject) =>
      jwt.verify(token, secret.toString(), verifyOptions, (err, decoded) =>
        err ? reject(err) : resolve(decoded as T)
      )
    ) as Promise<T>;
  }

  decode(
    token: string,
    options?: jwt.DecodeOptions
  ): null | { [key: string]: any } | string {
    return jwt.decode(token, options);
  }

  private mergeJwtOptions(
    options: jwt.VerifyOptions | jwt.SignOptions,
    key: 'verifyOptions' | 'signOptions'
  ): jwt.VerifyOptions | jwt.SignOptions {
    return options
      ? {
          ...(this.options[key] || {}),
          ...options
        }
      : this.options[key];
  }

  private getSecretKey(
    token: string | object | Buffer,
    options: jwt.VerifyOptions | jwt.SignOptions,
    key: 'publicKey' | 'privateKey',
    secretRequestType: JwtSecretRequestType
  ): string | Buffer | jwt.Secret {
    let secret = this.options.secretOrKeyProvider
      ? this.options.secretOrKeyProvider(secretRequestType, token, options)
      : this.options.secret || this.options[key];

    if (this.options.secretOrPrivateKey) {
      this.logger.warn(
        `"secretOrPrivateKey" has been deprecated, please use the new explicit "secret" or use "secretOrKeyProvider" or "privateKey"/"publicKey" exclusively.`
      );
      secret = this.options.secretOrPrivateKey;
    }
    return secret;
  }
}
