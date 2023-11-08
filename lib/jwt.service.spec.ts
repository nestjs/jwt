import { Test } from '@nestjs/testing';
import * as jwt from 'jsonwebtoken';
import {
  JwtModuleOptions,
  JwtSecretRequestType
} from './interfaces/jwt-module-options.interface';
import { JwtModule } from './jwt.module';
import { JwtService } from './jwt.service';
import { WrongSecretProviderError } from './jwt.errors';

const setup = async (config: JwtModuleOptions) => {
  const module = await Test.createTestingModule({
    imports: [JwtModule.register(config)]
  }).compile();

  return module.get<JwtService>(JwtService);
};

const config = {
  secretOrKeyProvider: (requestType: JwtSecretRequestType) =>
    requestType === JwtSecretRequestType.SIGN ? 'sign_secret' : 'verify_secret',
  secret: 'default_secret',
  publicKey: 'public_key',
  privateKey: 'private_key'
};

describe('JWT Service', () => {
  let verifySpy: jest.SpyInstance;
  let signSpy: jest.SpyInstance;
  let getRandomString = () => `${Date.now()}`;

  beforeEach(async () => {
    signSpy = jest
      .spyOn(jwt, 'sign')
      .mockImplementation((token, secret, options, callback) => {
        const result = 'signed_' + token + '_by_' + secret;
        return callback ? callback(null, result) : result;
      });

    verifySpy = jest
      .spyOn(jwt, 'verify')
      .mockImplementation((token, secret, options, callback) => {
        const result = 'verified_' + token + '_by_' + secret;
        return callback ? callback(null, result as any) : result;
      });
  });

  afterEach(() => {
    verifySpy.mockRestore();
    signSpy.mockRestore();
  });

  describe('should use config.secretOrKeyProvider', () => {
    let jwtService: JwtService;
    let testPayload: string = getRandomString();

    beforeAll(async () => {
      jwtService = await setup(config);
    });

    it('signing should use config.secretOrKeyProvider', async () => {
      expect(await jwtService.sign(testPayload)).toBe(
        `signed_${testPayload}_by_sign_secret`
      );
    });

    it('signing (async) should use config.secretOrKeyProvider', async () => {
      await expect(jwtService.signAsync(testPayload)).resolves.toBe(
        `signed_${testPayload}_by_sign_secret`
      );
    });

    it('verifying should use config.secretOrKeyProvider', async () => {
      expect(await jwtService.verify(testPayload)).toBe(
        `verified_${testPayload}_by_verify_secret`
      );
    });

    it('verifying (async) should use config.secretOrKeyProvider', async () => {
      await expect(jwtService.verifyAsync(testPayload)).resolves.toBe(
        `verified_${testPayload}_by_verify_secret`
      );
    });
  });

  describe('should use config.secret', () => {
    let jwtService: JwtService;
    let testPayload: string = getRandomString();

    beforeAll(async () => {
      jwtService = await setup({ ...config, secretOrKeyProvider: undefined });
    });

    it('signing should use config.secret', async () => {
      expect(await jwtService.sign(testPayload)).toBe(
        `signed_${testPayload}_by_default_secret`
      );
    });

    it('signing (async) should use config.secret', async () => {
      await expect(jwtService.signAsync(testPayload)).resolves.toBe(
        `signed_${testPayload}_by_default_secret`
      );
    });

    it('verifying should use config.secret', async () => {
      expect(await jwtService.verify(testPayload)).toBe(
        `verified_${testPayload}_by_default_secret`
      );
    });

    it('verifying (async) should use config.secret', async () => {
      await expect(jwtService.verifyAsync(testPayload)).resolves.toBe(
        `verified_${testPayload}_by_default_secret`
      );
    });
  });

  describe('should use config.privateKey and config.publicKey', () => {
    let jwtService: JwtService;
    let testPayload: string = getRandomString();

    beforeAll(async () => {
      jwtService = await setup({
        ...config,
        secretOrKeyProvider: undefined,
        secret: undefined
      });
    });

    it('signing should use config.privateKey', async () => {
      expect(await jwtService.sign(testPayload)).toBe(
        `signed_${testPayload}_by_private_key`
      );
    });

    it('signing (async) should use config.privateKey', async () => {
      await expect(jwtService.signAsync(testPayload)).resolves.toBe(
        `signed_${testPayload}_by_private_key`
      );
    });

    it('verifying should use config.publicKey', async () => {
      expect(await jwtService.verify(testPayload)).toBe(
        `verified_${testPayload}_by_public_key`
      );
    });

    it('verifying (async) should use config.publicKey', async () => {
      await expect(jwtService.verifyAsync(testPayload)).resolves.toBe(
        `verified_${testPayload}_by_public_key`
      );
    });
  });

  describe('should use config.secretOrPrivateKey but warn about deprecation', () => {
    let jwtService: JwtService;
    let consoleWarnSpy: jest.SpyInstance;
    let testPayload: string = getRandomString();

    beforeAll(async () => {
      jwtService = await setup({
        ...config,
        secretOrPrivateKey: 'deprecated_key'
      });
      consoleWarnSpy = jest.spyOn(jwtService['logger'], 'warn');
    });

    it('signing should use deprecated secretOrPrivateKey', async () => {
      expect(await jwtService.sign(testPayload)).toBe(
        `signed_${testPayload}_by_deprecated_key`
      );
      expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
    });

    it('signing (async) should use deprecated secretOrPrivateKey', async () => {
      await expect(jwtService.signAsync(testPayload)).resolves.toBe(
        `signed_${testPayload}_by_deprecated_key`
      );
      expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
    });

    it('verifying should use deprecated secretOrPrivateKey', async () => {
      expect(await jwtService.verify(testPayload)).toBe(
        `verified_${testPayload}_by_deprecated_key`
      );
      expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
    });

    it('verifying (async) should use deprecated secretOrPrivateKey', async () => {
      await expect(jwtService.verifyAsync(testPayload)).resolves.toBe(
        `verified_${testPayload}_by_deprecated_key`
      );
      expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
    });

    afterEach(async () => {
      consoleWarnSpy.mockClear();
    });
  });

  describe('should allow buffers for secrets', () => {
    let jwtService: JwtService;
    let secretB64: Buffer;
    let testPayload = { foo: 'bar' };

    beforeEach(async () => {
      secretB64 = Buffer.from('ThisIsARandomSecret', 'base64');
      jwtService = await setup({ secret: secretB64 });
      verifySpy.mockRestore();
      signSpy.mockRestore();
    });

    it('verifying should use base64 buffer key', async () => {
      let token = jwt.sign(testPayload, secretB64);

      expect(jwtService.verify(token)).toHaveProperty('foo', 'bar');
    });

    it('verifying (async) should use base64 buffer key', async () => {
      let token = jwt.sign(testPayload, secretB64);

      await expect(jwtService.verifyAsync(token)).resolves.toHaveProperty(
        'foo',
        'bar'
      );
    });
  });

  describe('should use secret key from options', () => {
    let jwtService: JwtService;
    let testPayload: string = getRandomString();

    beforeAll(async () => {
      jwtService = await setup({
        ...config,
        secretOrKeyProvider: undefined
      });
    });

    let secret = 'custom_secret';

    it('signing should use secret key from options', async () => {
      expect(await jwtService.sign(testPayload, { secret })).toBe(
        `signed_${testPayload}_by_custom_secret`
      );
    });

    it('signing (async) should use secret key from options', async () => {
      await expect(jwtService.signAsync(testPayload, { secret })).resolves.toBe(
        `signed_${testPayload}_by_custom_secret`
      );
    });

    it('verifying should use secret key from options', async () => {
      expect(await jwtService.verify(testPayload, { secret })).toBe(
        `verified_${testPayload}_by_custom_secret`
      );
    });

    it('verifying (async) should use secret key from options', async () => {
      await expect(
        jwtService.verifyAsync(testPayload, { secret })
      ).resolves.toBe(`verified_${testPayload}_by_custom_secret`);
    });
  });

  describe('should use private/public key from options', () => {
    let jwtService: JwtService;
    let testPayload: string = getRandomString();

    beforeAll(async () => {
      jwtService = await setup({
        ...config,
        secretOrKeyProvider: undefined,
        secret: undefined
      });
    });

    let privateKey = 'customPrivateKey';
    let publicKey = 'customPublicKey';

    it('signing should use private key from options', async () => {
      expect(await jwtService.sign(testPayload, { privateKey })).toBe(
        `signed_${testPayload}_by_customPrivateKey`
      );
    });

    it('signing (async) should use private key from options', async () => {
      await expect(
        jwtService.signAsync(testPayload, { privateKey })
      ).resolves.toBe(`signed_${testPayload}_by_customPrivateKey`);
    });

    it('verifying should use public key from options', async () => {
      expect(await jwtService.verify(testPayload, { publicKey })).toBe(
        `verified_${testPayload}_by_customPublicKey`
      );
    });

    it('verifying (async) should use public key from options', async () => {
      await expect(
        jwtService.verifyAsync(testPayload, { publicKey })
      ).resolves.toBe(`verified_${testPayload}_by_customPublicKey`);
    });
  });

  describe('should not use invalid sign options', () => {
    let jwtService: JwtService;
    let testPayloadStr: string = getRandomString();

    beforeAll(async () => {
      jwtService = await setup({ secretOrKeyProvider: undefined });
    });

    it('should not "sign" expect errors with a "payload" string and "secret"', () => {
      // @ts-expect-no-error
      expect(() => jwtService.sign(testPayloadStr, { secret: 'secret' }));
    });

    it('should not "signAsync" expect errors with a "payload" string and "privateKey"', () => {
      // @ts-expect-no-error
      expect(() =>
        jwtService.signAsync(testPayloadStr, { privateKey: 'privateKey' })
      );
    });
  });

  describe('should use invalid sign options', () => {
    const signOptions: jwt.SignOptions = {
      expiresIn: '1d'
    };

    let jwtService: JwtService;
    let testPayloadStr: string = getRandomString();
    let testPayloadObj: object = {};

    beforeAll(async () => {
      jwtService = await setup({ signOptions, secretOrKeyProvider: undefined });
    });

    it('should "sign" expect errors with a "payload" string with "expiresIn"', () => {
      expect(() =>
        // @ts-expect-error
        jwtService.sign(testPayloadStr, { expiresIn: 60 })
      ).toThrowError(
        'Payload as string is not allowed with the following sign options: expiresIn'
      );
    });

    it('should "signAsync" expect errors with a "payload" string with "notBefore"', () => {
      expect(() =>
        // @ts-expect-error
        jwtService.signAsync(testPayloadStr, { notBefore: 60 })
      ).toThrowError(
        'Payload as string is not allowed with the following sign options: expiresIn, notBefore'
      );
    });

    it('should not "sign" expect errors with a "payload" object with "notBefore" ', () => {
      // @ts-expect-no-error
      expect(() => jwtService.sign(testPayloadObj, { notBefore: 60 }));
    });

    it('should not "signAsync" expect errors with a "payload" object with "notBefore" ', () => {
      // @ts-expect-no-error
      expect(() => jwtService.signAsync(testPayloadObj, { notBefore: 60 }));
    });

    it('should "sign" expect errors using "payload" string with already defined invalid sign options', () => {
      expect(() => jwtService.sign(testPayloadStr)).toThrowError(
        'Payload as string is not allowed with the following sign options: expiresIn'
      );
    });

    it('should "signAsync" expect errors using "payload" string with already defined invalid sign options', () => {
      expect(() => jwtService.signAsync(testPayloadStr)).toThrowError(
        'Payload as string is not allowed with the following sign options: expiresIn'
      );
    });
  });
});
