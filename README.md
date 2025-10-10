<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[travis-image]: https://api.travis-ci.org/nestjs/nest.svg?branch=master
[travis-url]: https://travis-ci.org/nestjs/nest
[linux-image]: https://img.shields.io/travis/nestjs/nest/master.svg?label=linux
[linux-url]: https://travis-ci.org/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore"><img src="https://img.shields.io/npm/dm/@nestjs/core.svg" alt="NPM Downloads" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec"><img src="https://img.shields.io/badge/Donate-PayPal-dc3d53.svg"/></a>
  <a href="https://twitter.com/nestframework"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Description

JWT utilities module for [Nest](https://github.com/nestjs/nest) based on the [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) package.

## Installation

```bash
$ npm i --save @nestjs/jwt
```

## Usage

Import `JwtModule`:

```typescript
@Module({
  imports: [JwtModule.register({ secret: 'hard!to-guess_secret' })],
  providers: [...],
})
export class AuthModule {}
```

Inject `JwtService`:

```typescript
@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}
}
```

## Secret / Encryption Key options

If you want to control secret and key management dynamically you can use the `secretOrKeyProvider` function for that purpose. You also can use asynchronous version of `secretOrKeyProvider`.
NOTE: For asynchronous version of `secretOrKeyProvider`, synchronous versions of `.sign()` and `.verify()` will throw an exception.

```typescript
JwtModule.register({
   /* Secret has precedence over keys */
  secret: 'hard!to-guess_secret',

  /* public key used in asymmetric algorithms (required if non other secrets present) */
  publicKey: '...',

  /* private key used in asymmetric algorithms (required if non other secrets present) */
  privateKey: '...',

  /* Dynamic key provider has precedence over static secret or pub/private keys */
  secretOrKeyProvider: (
    requestType: JwtSecretRequestType,
    tokenOrPayload: string | Object | Buffer,
    verifyOrSignOrOptions?: jwt.VerifyOptions | jwt.SignOptions
  ) => {
    switch (requestType) {
      case JwtSecretRequestType.SIGN:
        // retrieve signing key dynamically
        return 'privateKey';
      case JwtSecretRequestType.VERIFY:
        // retrieve public key for verification dynamically
        return 'publicKey';
      default:
        // retrieve secret dynamically
        return 'hard!to-guess_secret';
    }
  },
});
```

## Async options

Quite often you might want to asynchronously pass your module options instead of passing them beforehand. In such case, use `registerAsync()` method, that provides a couple of various ways to deal with async data.

**1. Use factory**

```typescript
JwtModule.registerAsync({
  useFactory: () => ({
    secret: 'hard!to-guess_secret'
  })
});
```

Obviously, our factory behaves like every other one (might be `async` and is able to inject dependencies through `inject`).

```typescript
JwtModule.registerAsync({
  imports: [ConfigModule],
  useFactory: async (configService: ConfigService) => ({
    secret: configService.get<string>('SECRET'),
  }),
  inject: [ConfigService],
}),
```

**2. Use class**

```typescript
JwtModule.registerAsync({
  useClass: JwtConfigService
});
```

Above construction will instantiate `JwtConfigService` inside `JwtModule` and will leverage it to create options object.

```typescript
class JwtConfigService implements JwtOptionsFactory {
  createJwtOptions(): JwtModuleOptions {
    return {
      secret: 'hard!to-guess_secret'
    };
  }
}
```

**3. Use existing**

```typescript
JwtModule.registerAsync({
  imports: [ConfigModule],
  useExisting: ConfigService,
}),
```

It works the same as `useClass` with one critical difference - `JwtModule` will lookup imported modules to reuse already created `ConfigService`, instead of instantiating it on its own.

## API Spec

The `JwtService` uses [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) underneath.

#### jwtService.sign(payload: string | Object | Buffer, options?: JwtSignOptions): string

The sign method is an implementation of jsonwebtoken `.sign()`. Differing from jsonwebtoken it also allows an additional `secret`, `privateKey`, and `publicKey` properties on `options` to override options passed in from the module. It only overrides the `secret`, `publicKey` or `privateKey` though not a `secretOrKeyProvider`.
NOTE: Will throw an exception for asynchronous version of `secretOrKeyProvider`;

#### jwtService.signAsync(payload: string | Object | Buffer, options?: JwtSignOptions): Promise\<string\>

The asynchronous `.sign()` method.

#### jwtService.verify\<T extends object = any>(token: string, options?: JwtVerifyOptions): T

The verify method is an implementation of jsonwebtoken `.verify()`. Differing from jsonwebtoken it also allows an additional `secret`, `privateKey`, and `publicKey` properties on `options` to override options passed in from the module. It only overrides the `secret`, `publicKey` or `privateKey` though not a `secretOrKeyProvider`.
NOTE: Will throw an exception for asynchronous version of `secretOrKeyProvider`;

#### jwtService.verifyAsync\<T extends object = any>(token: string, options?: JwtVerifyOptions): Promise\<T\>

The asynchronous `.verify()` method.

#### jwtService.decode(token: string, options: DecodeOptions): object | string

The decode method is an implementation of jsonwebtoken `.decode()`.

The `JwtModule` takes an `options` object:

- `secret` is either a string, buffer, or object containing the secret for HMAC algorithms
- `secretOrKeyProvider` function with the following signature `(requestType, tokenOrPayload, options?) => jwt.Secret | Promise<jwt.Secret>` (allows generating either secrets or keys dynamically)
- `signOptions` [read more](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback)
- `privateKey` PEM encoded private key for RSA and ECDSA with passphrase an object `{ key, passphrase }` [read more](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback)
- `publicKey` PEM encoded public key for RSA and ECDSA
- `verifyOptions` [read more](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback)
- `secretOrPrivateKey` (DEPRECATED!) [read more](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback)

For performance purposes, it is advised to pass instances of `KeyObject` to `secret`, `privateKey` and `publicKey` properties of this `options` object. These `KeyObject` can be generated with `createSecretKey()`, `createPrivateKey()` and `createPublicKey()` from Node.js `crypto` module. For example:

```typescript
import { createSecretKey } from 'crypto';

new JwtService({
  secret: createSecretKey(Buffer.from('the secret key'))
});
```

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](LICENSE).
