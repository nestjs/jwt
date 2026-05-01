import { JwtModuleOptions } from './interfaces/jwt-module-options.interface.js';
import { JWT_MODULE_OPTIONS } from './jwt.constants.js';

/**
 * @publicApi
 */
export function createJwtProvider(options: JwtModuleOptions): any[] {
  return [{ provide: JWT_MODULE_OPTIONS, useValue: options || {} }];
}
