import jsonwebtoken from 'jsonwebtoken';
import type * as jwt from 'jsonwebtoken';

export * from './interfaces/index.js';
export * from './jwt.errors.js';
export * from './jwt.module.js';
export * from './jwt.service.js';

// `jsonwebtoken` is CommonJS and its named exports are not statically
// detectable, so they cannot be re-exported directly under ESM. Each error is
// re-declared as a value (for `instanceof` checks) and as a type.
type TokenExpiredError = jwt.TokenExpiredError;
const TokenExpiredError = jsonwebtoken.TokenExpiredError;

type NotBeforeError = jwt.NotBeforeError;
const NotBeforeError = jsonwebtoken.NotBeforeError;

type JsonWebTokenError = jwt.JsonWebTokenError;
const JsonWebTokenError = jsonwebtoken.JsonWebTokenError;

export { TokenExpiredError, NotBeforeError, JsonWebTokenError };
