import * as jwt from 'jsonwebtoken';
import * as express from 'express';
import { set } from './util/set';
import { decode } from 'jws';

import { UnauthorizedError } from './errors/UnauthorizedError';


/**
 * Returns the decoded payload without verifying if the signature is valid.
 * token - JWT string to decode
 * [options] - Options for decoding
 * returns - The decoded Token
 * 
 * @see https://github.com/auth0/node-jsonwebtoken/blob/master/decode.js
 * Implementation is copied from there, to minimize package size.
 * We add typings and modern language features.
 */
function jwtDecode(token: string, options: jwt.DecodeOptions = {}) {
  // jws.decode API typings are inaccurate
  // @ts-ignore-next-line
  const decoded = decode(token, options);
  if (!decoded) { return null; }
  let payload = decoded.payload;

  //try parse the payload
  if (typeof payload === 'string') {
    try {
      const obj = JSON.parse(payload);
      if(obj !== null && typeof obj === 'object') {
        payload = obj;
      }
    } catch (e) 
    // eslint-disable-next-line no-empty
    { }
  }

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  if (options.complete === true) {
    return {
      header: decoded.header,
      payload: payload,
      signature: decoded.signature
    };
  }
  return payload;
}

/**
 * A function to customize how a token is retrieved from the express request.
 */
export type TokenGetter = (req: express.Request) => string | Promise<string> | undefined;

export type Params = {
  /**
   * Defines how to retrieves the token from the request object.
   */
  getToken?: TokenGetter,

  /**
   * If sets to true, continue to the next middleware when the
   * request doesn't include a token without failing.
   *
   * @default true
   */
  credentialsRequired?: boolean,

  /**
   * Allows to customize the name of the property in the request object
   * where the decoded payload is set.
   * @default 'auth'
   */
  requestProperty?: string,
};

export { UnauthorizedError } from './errors/UnauthorizedError';

/**
 * @deprecated this breaks tsc when using strict: true
 */
export type ExpressJwtRequest<T = jwt.JwtPayload> =
  express.Request & { auth: T }

/**
 * @deprecated use Request<T>
 */
export type ExpressJwtRequestUnrequired<T = jwt.JwtPayload> =
  express.Request & { auth?: T }

/**
 * The Express Request including the "auth" property with the decoded JWT payload.
 */
export type Request<T = jwt.JwtPayload> =
  express.Request & { auth?: T };

/**
 * Returns an express middleware to decode JWTs.
 *
 * @param options {Params}
 * @returns the express middleware function
 * 
 * @see https://github.com/auth0/express-jwt
 * The implementation is largely copied from there, less the logic to verify if the signature is valid based on secret.
 */
export const expressdecodejwt = (options: Params = {}) => {
  const credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;
  const requestProperty = typeof options.requestProperty === 'string' ? options.requestProperty : 'auth';

  const middleware = async function (req: express.Request, res: express.Response, next: express.NextFunction) {
    let token: string;
    try {
      if (req.method === 'OPTIONS' && 'access-control-request-headers' in req.headers) {
        const hasAuthInAccessControl = req.headers['access-control-request-headers']
          .split(',')
          .map(header => header.trim().toLowerCase())
          .includes('authorization');
        if (hasAuthInAccessControl) {
          return setImmediate(next);
        }
      }

      const authorizationHeader = req.headers && 'Authorization' in req.headers ? 'Authorization' : 'authorization';
      if (options.getToken && typeof options.getToken === 'function') {
        token = await options.getToken(req);
      } else if (req.headers && req.headers[authorizationHeader]) {
        const parts = (req.headers[authorizationHeader] as string).split(' ');
        if (parts.length == 2) {
          const scheme = parts[0];
          const credentials = parts[1];

          if (/^Bearer$/i.test(scheme)) {
            token = credentials;
          } else {
            if (credentialsRequired) {
              throw new UnauthorizedError('credentials_bad_scheme', { message: 'Format is Authorization: Bearer [token]' });
            } else {
              return next();
            }
          }
        } else {
          throw new UnauthorizedError('credentials_bad_format', { message: 'Format is Authorization: Bearer [token]' });
        }
      }

      if (!token) {
        if (credentialsRequired) {
          throw new UnauthorizedError('credentials_required', { message: 'No authorization token was found' });
        } else {
          return next();
        }
      }

      let decodedToken: jwt.Jwt;

      console.log(token);
      try {
        decodedToken = jwtDecode(token, { complete: true });
      } catch (err) {
        throw new UnauthorizedError('invalid_token', err);
      }

      if (decodedToken === null) {
        throw new UnauthorizedError('invalid_token', { message: 'Could not decode JWT' });
      }

      const request = req as Request<jwt.JwtPayload | string>;
      set(request, requestProperty, decodedToken.payload);
      setImmediate(next);
    } catch (err) {
      setImmediate(next, err);
    }
  };

  return middleware;
}
