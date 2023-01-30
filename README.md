# express-decode-jwt

This module provides Express middleware for decoding JWTs ([JSON Web Tokens](https://jwt.io)) through the [jws](https://github.com/auth0/node-jws/) module. The decoded JWT payload is made available on the request object. This package is largely the same as the [express-jwt](https://github.com/auth0/express-jwt/) module, simplified to remove the verification of JWTs.

This may be suitable for applications where your express server is fronted by an ingress that has already verified the token, which can avoid having to manage access to secrets in your express server.

> **Warning:** This middleware will not verify whether the signature is valid. You should not use this for untrusted messages.

You should ensure that the request is verified before being handled by this middleware, for example by some prior middleware or an ingress fronting your express server. Namely, the verification should ensure that the token exists, is in the expected format, and is valid. Otherwise, the message should be treated as untrusted, and should not reach this middleware.

You should ensure that this middleware retrieves the JWT from the request in the *exact* same way it is retrieved for verification. This is important because discrepancies could allow an attacker to craft a request with a valid JWT that satisfies the verification, and a secondary JWT that bypasses verification to be retrieved and decoded by your express server. By default, this middleware extracts the JWT from the `Authorization` header (or its lowercase counterpart, since header names are not case sensitive, see [RFC 2616 - "Hypertext Transfer Protocol -- HTTP/1.1" Section 4.2, "Message Headers"](http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2)) as an [OAuth2 Bearer token](https://oauth.net/2/bearer-tokens/). Assuming the verification also extracts the JWT in this standard way, this should only be a concern if implementing the `getToken` option yourself, which is why its usage is strongly discouraged in the context of this package.

> **Warning:** When the token comes from an untrusted source (e.g. user input or external request), the returned decoded payload should be treated like any other user input; please make sure to sanitize and only work with properties that are expected.

## Install

```
$ npm install express-decode-jwt
```

## API

`expressdecodejwt(options?: Params)`

Options has the following parameters:

- `getToken?: TokenGetter` (optional): A function that receives the express `Request` and returns the token, by default it looks in the `Authorization` header. Usage of this option is strongly discouraged, for security reasons.
- `credentialsRequired?: boolean` (optional): If it's false, continue to the next middleware if the request does not contain a token instead of failing, defaults to true.
- `requestProperty?: string` (optional): Name of the property in the request object where the payload is set. Default to `req.auth`.

The available functions have the following interface:

- `TokenGetter = (req: express.Request) => string | Promise<string> | undefined;`

## Usage

Basic usage:

```javascript
var { expressdecodejwt: decodeJwt } = require("express-decode-jwt");
// or ES6
// import { expressdecodejwt as decodeJwt } from "express-jwt";

app.get(
  "/private",
  decodeJwt(),
  function (req, res) {
    const authorizedSubject = "1234567890";
    if (req.auth.sub !=== authorizedSubject) return res.sendStatus(401);
    res.sendStatus(200);
  }
);
```

The decoded JWT payload is available on the request via the `auth` property.

> The default behavior of the module is to extract the JWT from the `Authorization` header as an [OAuth2 Bearer token](https://oauth.net/2/bearer-tokens/).

### Usage with express routing

To only protect specific paths (e.g. beginning with `/api`), use [express router](https://expressjs.com/en/4x/api.html#app.use) call `use`, like so:

```javascript
app.use("/api", decodeJwt({ secret: "shhhhhhared-secret", algorithms: ["HS256"] }));
```

### Customizing Token Location

A custom function for extracting the token from a request can be specified with
the `getToken` option. This is useful if you need to pass the token through a
query parameter or a cookie. You can throw an error in this function and it will
be handled by `express-jwt`.

```javascript
app.use(
  decodeJwt({
    credentialsRequired: false,
    getToken: function fromHeaderOrQuerystring(req) {
      if (
        req.headers.authorization &&
        req.headers.authorization.split(" ")[0] === "Bearer"
      ) {
        return req.headers.authorization.split(" ")[1];
      } else if (req.query && req.query.token) {
        return req.query.token;
      }
      return null;
    }
  })
);
```

> **Warning:** for security reasons, usage of the `getToken` option is strongly discouraged in the context of this package.

### Error handling

The default behavior is to throw an error when the token is invalid, so you can add your custom logic to manage unauthorized access as follows:

```javascript
app.use(function (err, req, res, next) {
  if (err.name === "UnauthorizedError") {
    res.status(401).send("invalid token...");
  } else {
    next(err);
  }
});
```

> The thrown `UnauthorizedError` is a misnomer, as the validation performed by this middleware is insufficient to assert that the request is authorized.

You might want to use this module to identify registered users while still providing access to unregistered users. You can do this by using the option `credentialsRequired`:

```javascript
app.use(decodeJwt({ credentialsRequired: false }));
```

## Typescript

A `Request` type is provided from `express-decode-jwt`, which extends `express.Request` with the `auth` property. It could be aliased, like how `JWTRequest` is below.

```typescript
import { expressdecodejwt as decodeJwt, Request as JWTRequest } from "express-decode-jwt";

app.get(
  "/private",
  decodeJwt(),
  function (req: JWTRequest, res: express.Response) {
    iconst authorizedSubject = "1234567890";
    if (req.auth?.sub !=== authorizedSubject) return res.sendStatus(401);
    res.sendStatus(200);
  }
);
```

## Related Modules

- [express-jwt](https://github.com/auth0/express-jwt/) - JWT verification (and decoding) middleware
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) — JSON Web Token sign and verification
- [express-jwt-permissions](https://github.com/MichielDeMey/express-jwt-permissions) - Permissions middleware for JWT tokens

## Tests

```
$ npm install
$ npm test
```

## Contributors

Check them out [here](https://github.com/loucadufault/express-decode-jwt/graphs/contributors) and [here](https://github.com/auth0/express-jwt/graphs/contributors)

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
