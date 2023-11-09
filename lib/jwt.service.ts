import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import {
  GetSecretKeyResult,
  JwtModuleOptions,
  JwtSecretRequestType,
  JwtSignOptions,
  JwtVerifyOptions
} from './interfaces';
import { JWT_MODULE_OPTIONS } from './jwt.constants';
import { WrongSecretProviderError } from './jwt.errors';

@Injectable()
export class JwtService {
  private readonly logger = new Logger('JwtService');

  constructor(
    @Optional()
    @Inject(JWT_MODULE_OPTIONS)
    private readonly options: JwtModuleOptions = {}
  ) {}

  sign(
    payload: string,
    options?: Omit<JwtSignOptions, keyof jwt.SignOptions>
  ): string;
  sign(payload: Buffer | object, options?: JwtSignOptions): string;
  sign(payload: string | Buffer | object, options?: JwtSignOptions): string {
    const signOptions = this.mergeJwtOptions(
      { ...options },
      'signOptions'
    ) as jwt.SignOptions;
    const secret = this.getSecretKey(
      payload,
      options,
      'privateKey',
      JwtSecretRequestType.SIGN
    );

    if (secret instanceof Promise) {
      secret.catch(() => {}); // suppress rejection from async provider
      this.logger.warn(
        'For async version of "secretOrKeyProvider", please use "signAsync".'
      );
      throw new WrongSecretProviderError();
    }

    const allowedSignOptKeys = ['secret', 'privateKey'];
    const signOptKeys = Object.keys(signOptions);
    if (
      typeof payload === 'string' &&
      signOptKeys.some((k) => !allowedSignOptKeys.includes(k))
    ) {
      throw new Error(
        'Payload as string is not allowed with the following sign options: ' +
          signOptKeys.join(', ')
      );
    }

    return jwt.sign(payload, secret, signOptions);
  }

  signAsync(
    payload: string,
    options?: Omit<JwtSignOptions, keyof jwt.SignOptions>
  ): Promise<string>;
  signAsync(
    payload: Buffer | object,
    options?: JwtSignOptions
  ): Promise<string>;
  signAsync(
    payload: string | Buffer | object,
    options?: JwtSignOptions
  ): Promise<string> {
    const signOptions = this.mergeJwtOptions(
      { ...options },
      'signOptions'
    ) as jwt.SignOptions;
    const secret = this.getSecretKey(
      payload,
      options,
      'privateKey',
      JwtSecretRequestType.SIGN
    );

    const allowedSignOptKeys = ['secret', 'privateKey'];
    const signOptKeys = Object.keys(signOptions);
    if (
      typeof payload === 'string' &&
      signOptKeys.some((k) => !allowedSignOptKeys.includes(k))
    ) {
      throw new Error(
        'Payload as string is not allowed with the following sign options: ' +
          signOptKeys.join(', ')
      );
    }

    return new Promise((resolve, reject) =>
      Promise.resolve()
        .then(() => secret)
        .then((scrt: GetSecretKeyResult) => {
          jwt.sign(payload, scrt, signOptions, (err, encoded) =>
            err ? reject(err) : resolve(encoded)
          )
        })
    );
  }

  verify<T extends object = any>(token: string, options?: JwtVerifyOptions): T {
    const verifyOptions = this.mergeJwtOptions({ ...options }, 'verifyOptions');
    const secret = this.getSecretKey(
      token,
      options,
      'publicKey',
      JwtSecretRequestType.VERIFY
    );

    if (secret instanceof Promise) {
      secret.catch(() => {}); // suppress rejection from async provider
      this.logger.warn(
        'For async version of "secretOrKeyProvider", please use "verifyAsync".'
      );
      throw new WrongSecretProviderError();
    }

    return jwt.verify(token, secret, verifyOptions) as T;
  }

  verifyAsync<T extends object = any>(
    token: string,
    options?: JwtVerifyOptions
  ): Promise<T> {
    const verifyOptions = this.mergeJwtOptions({ ...options }, 'verifyOptions');
    const secret = this.getSecretKey(
      token,
      options,
      'publicKey',
      JwtSecretRequestType.VERIFY
    );

    return new Promise((resolve, reject) =>
      Promise.resolve()
        .then(() => secret)
        .then((scrt: GetSecretKeyResult) => {
          jwt.verify(token, scrt, verifyOptions, (err, decoded) =>
            err ? reject(err) : resolve(decoded as T)
          )
        })
        .catch(reject)
    ) as Promise<T>;
  }

  decode<T = any>(
    token: string,
    options?: jwt.DecodeOptions
  ): T {
    return jwt.decode(token, options) as T;
  }

  private mergeJwtOptions(
    options: JwtVerifyOptions | JwtSignOptions,
    key: 'verifyOptions' | 'signOptions'
  ): jwt.VerifyOptions | jwt.SignOptions {
    delete options.secret;
    if (key === 'signOptions') {
      delete (options as JwtSignOptions).privateKey;
    } else {
      delete (options as JwtVerifyOptions).publicKey;
    }
    return options
      ? {
          ...(this.options[key] || {}),
          ...options
        }
      : this.options[key];
  }

  private overrideSecretFromOptions(secret: GetSecretKeyResult) {
    if (this.options.secretOrPrivateKey) {
      this.logger.warn(
        `"secretOrPrivateKey" has been deprecated, please use the new explicit "secret" or use "secretOrKeyProvider" or "privateKey"/"publicKey" exclusively.`
      );
      secret = this.options.secretOrPrivateKey;
    }

    return secret;
  }

  private getSecretKey(
    token: string | object | Buffer,
    options: JwtVerifyOptions | JwtSignOptions,
    key: 'publicKey' | 'privateKey',
    secretRequestType: JwtSecretRequestType
  ): GetSecretKeyResult | Promise<GetSecretKeyResult> {
    const secret = this.options.secretOrKeyProvider
      ? this.options.secretOrKeyProvider(secretRequestType, token, options)
      : options?.secret ||
        this.options.secret ||
        (key === 'privateKey'
          ? (options as JwtSignOptions)?.privateKey || this.options.privateKey
          : (options as JwtVerifyOptions)?.publicKey ||
            this.options.publicKey) ||
        this.options[key];

    return secret instanceof Promise
      ? secret.then((sec) => this.overrideSecretFromOptions(sec))
      : this.overrideSecretFromOptions(secret);
  }
}
