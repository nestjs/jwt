import { JwtModuleOptions } from './interfaces/jwt-module-options.interface';
import { JWT_MODULE_OPTIONS } from './jwt.constants';

export function createJwtProvider(options: JwtModuleOptions): any[] {
  return [{ provide: JWT_MODULE_OPTIONS, useValue: options || {} }];
}
