export * from './interfaces/index.js';
export * from './jwt.errors.js';
export * from './jwt.module.js';
export * from './jwt.service.js';
import * as jwt from 'jsonwebtoken';

export const TokenExpiredError = jwt.TokenExpiredError;
export const NotBeforeError = jwt.NotBeforeError;
export const JsonWebTokenError = jwt.JsonWebTokenError;
