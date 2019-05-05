import { Inject, Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import {
  JwtModuleOptions,
  JwtSecretRequestType
} from './interfaces/jwt-module-options.interface';
import { JWT_MODULE_OPTIONS } from './jwt.constants';

@Injectable()
export class JwtService {
  constructor(
    @Inject(JWT_MODULE_OPTIONS) private readonly options: JwtModuleOptions
  ) {}

  sign(payload: string | Buffer | object, options?: jwt.SignOptions): string {
    const signOptions = options
      ? {
          ...(this.options.signOptions || {}),
          ...options
        }
      : this.options.signOptions;

    let secret = this.options.secretOrKeyProvider
      ? this.options.secretOrKeyProvider(
          JwtSecretRequestType.SIGN,
          payload,
          signOptions
        )
      : this.options.secret || this.options.privateKey;

    if (this.options.secretOrPrivateKey) {
      console.warn(
        "WARNING! 'secretOrPrivateKey' has been deprecated, please use the ",
        "new explicit 'secretOrKeyProvider' or use 'privateKey'/'publicKey' exclusively"
      );
      secret = this.options.secretOrPrivateKey;
    }

    return jwt.sign(payload, secret, signOptions);
  }

  signAsync(
    payload: string | Buffer | object,
    options?: jwt.SignOptions
  ): Promise<string> {
    const signOptions = options
      ? {
          ...(this.options.signOptions || {}),
          ...options
        }
      : this.options.signOptions;

    let secret = this.options.secretOrKeyProvider
      ? this.options.secretOrKeyProvider(
          JwtSecretRequestType.SIGN,
          payload,
          signOptions
        )
      : this.options.secret || this.options.privateKey;

    if (this.options.secretOrPrivateKey) {
      console.warn(
        "WARNING! 'secretOrPrivateKey' has been deprecated, please use the ",
        "new explicit 'secretOrKeyProvider' or use 'privateKey'/'publicKey' exclusively"
      );
      secret = this.options.secretOrPrivateKey;
    }

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
    const verifyOptions = options
      ? {
          ...(this.options.verifyOptions || {}),
          ...options
        }
      : this.options.verifyOptions;

    let secret = this.options.secretOrKeyProvider
      ? this.options.secretOrKeyProvider(
          JwtSecretRequestType.VERIFY,
          token,
          verifyOptions
        )
      : this.options.secret || this.options.publicKey;

    if (this.options.secretOrPrivateKey) {
      console.warn(
        "WARNING! 'secretOrPrivateKey' has been deprecated, please use the ",
        "new explicit 'secretOrKeyProvider' or use 'privateKey'/'publicKey' exclusively"
      );
      secret = this.options.publicKey;
    }

    return jwt.verify(token, secret.toString(), verifyOptions) as T;
  }

  verifyAsync<T extends object = any>(
    token: string,
    options?: jwt.VerifyOptions
  ): Promise<T> {
    const verifyOptions = options
      ? {
          ...(this.options.verifyOptions || {}),
          ...options
        }
      : this.options.verifyOptions;

    let secret = this.options.secretOrKeyProvider
      ? this.options.secretOrKeyProvider(
          JwtSecretRequestType.VERIFY,
          token,
          verifyOptions
        )
      : this.options.secret || this.options.publicKey;

    if (this.options.secretOrPrivateKey) {
      console.warn(
        "WARNING! 'secretOrPrivateKey' has been deprecated, please use the ",
        "new explicit 'secretOrKeyProvider' or use 'privateKey'/'publicKey' exclusively"
      );
      secret = this.options.publicKey;
    }

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
}
