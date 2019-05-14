import { Test } from '@nestjs/testing';
import * as jwt from 'jsonwebtoken';
import {
  JwtModuleOptions,
  JwtSecretRequestType
} from './interfaces/jwt-module-options.interface';
import { JwtModule } from './jwt.module';
import { JwtService } from './jwt.service';

const setup = async (config: JwtModuleOptions) => {
  const module = await Test.createTestingModule({
    imports: [JwtModule.register(config)]
  }).compile();

  return module.get<JwtService>(JwtService);
};

const config = {
  secretOrKeyProvider: (requestType: JwtSecretRequestType) =>
    requestType === JwtSecretRequestType.SIGN ? 'S' : 'V',
  secret: 'B',
  publicKey: 'C',
  privateKey: 'D'
};

describe('JWT Service', () => {
  beforeAll(async () => {
    jest
      .spyOn(jwt, 'sign')
      .mockImplementation((token, secret, options) => secret);

    jest
      .spyOn(jwt, 'verify')
      .mockImplementation((token, secret, options) => secret);
  });

  describe('should use secretOrKeyProvider', () => {
    let jwtService: JwtService;

    beforeAll(async () => {
      jwtService = await setup(config);
    });

    it('signing should use SIGN option function', async () => {
      expect(await jwtService.sign('random')).toBe(
        config.secretOrKeyProvider(JwtSecretRequestType.SIGN)
      );
    });

    it('signing (async) should use SIGN option function', async () => {
      expect(jwtService.signAsync('random')).resolves.toBe(
        config.secretOrKeyProvider(JwtSecretRequestType.SIGN)
      );
    });

    it('verifying should use VERIFY option function', async () => {
      expect(await jwtService.verify('random')).toBe(
        config.secretOrKeyProvider(JwtSecretRequestType.VERIFY)
      );
    });

    it('verifying (async) should use SIGN option function', async () => {
      expect(jwtService.verifyAsync('random')).resolves.toBe(
        config.secretOrKeyProvider(JwtSecretRequestType.VERIFY)
      );
    });
  });

  describe('should use secret', () => {
    let jwtService: JwtService;

    beforeAll(async () => {
      jwtService = await setup({ ...config, secretOrKeyProvider: undefined });
    });

    it('signing should use secret key', async () => {
      expect(await jwtService.sign('random')).toBe(config.secret);
    });

    it('signing (async) should use secret key', async () => {
      expect(jwtService.signAsync('random')).resolves.toBe(config.secret);
    });

    it('verifying should use secret key', async () => {
      expect(await jwtService.verify('random')).toBe(config.secret);
    });

    it('verifying (async) should use secret key', async () => {
      expect(jwtService.verifyAsync('random')).resolves.toBe(config.secret);
    });
  });

  describe('should use public/private key', () => {
    let jwtService: JwtService;

    beforeAll(async () => {
      jwtService = await setup({
        ...config,
        secretOrKeyProvider: undefined,
        secret: undefined
      });
    });

    it('signing should use private key', async () => {
      expect(await jwtService.sign('random')).toBe(config.privateKey);
    });

    it('signing (async) should use private key', async () => {
      expect(jwtService.signAsync('random')).resolves.toBe(config.privateKey);
    });

    it('verifying should use public key', async () => {
      expect(await jwtService.verify('random')).toBe(config.publicKey);
    });

    it('verifying (async) should use public key', async () => {
      expect(jwtService.verifyAsync('random')).resolves.toBe(config.publicKey);
    });
  });

  describe('override but warn deprecation for "secretOrKey"', () => {
    let jwtService: JwtService;
    let consoleCheck: jest.SpyInstance;

    beforeAll(async () => {
      jwtService = await setup({ ...config, secretOrPrivateKey: 'deprecated' });
      consoleCheck = jest.spyOn(jwtService['logger'], 'warn');
    });

    it('signing should use deprecated secretOrPrivateKey', async () => {
      expect(await jwtService.sign('random')).toBe('deprecated');
      expect(consoleCheck).toHaveBeenCalledTimes(1);
    });

    it('signing (async) should use deprecated secretOrPrivateKey', async () => {
      expect(jwtService.signAsync('random')).resolves.toBe('deprecated');
      expect(consoleCheck).toHaveBeenCalledTimes(1);
    });

    it('verifying should use deprecated secretOrPrivateKey', async () => {
      expect(await jwtService.verify('random')).toBe('deprecated');
      expect(consoleCheck).toHaveBeenCalledTimes(1);
    });

    it('verifying (async) should use deprecated secretOrPrivateKey', async () => {
      expect(jwtService.verifyAsync('random')).resolves.toBe('deprecated');
      expect(consoleCheck).toHaveBeenCalledTimes(1);
    });

    afterEach(async () => {
      consoleCheck.mockClear();
    });
  });
});
