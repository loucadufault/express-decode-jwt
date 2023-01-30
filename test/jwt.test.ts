import * as jwt from 'jsonwebtoken';
import * as express from 'express';
import { expressdecodejwt, UnauthorizedError, Request } from '../src';
import * as assert from 'assert';


describe('failure tests', function () {
  let req: express.Request;
  let res: express.Response;

  this.beforeEach(() => {
    req = {} as express.Request;
    res = {} as express.Response;
  });

  it('should throw if no authorization header and credentials are required', function (done) {
    expressdecodejwt({ credentialsRequired: true })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_required');
      done();
    });
  });

  it('should skip on CORS preflight', function (done) {
    const corsReq = {} as express.Request;
    corsReq.method = 'OPTIONS';
    corsReq.headers = {
      'access-control-request-headers': 'sasa, sras,  authorization'
    };
    expressdecodejwt()(corsReq, res, function (err) {
      assert.ok(!err);
      done();
    });
  });

  it('should throw if authorization header is malformed', function (done) {
    req.headers = {};
    req.headers.authorization = 'wrong';
    expressdecodejwt()(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_bad_format');
      done();
    });
  });

  it('should throw if authorization header is not Bearer', function () {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    expressdecodejwt()(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_bad_scheme');
    });
  });

  it('should next if authorization header is not Bearer and credentialsRequired is false', function (done) {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    expressdecodejwt({ credentialsRequired: false })(req, res, function (err) {
      assert.ok(typeof err === 'undefined');
      done();
    });
  });

  it('should throw if authorization header is not well-formatted jwt', function (done) {
    req.headers = {};
    req.headers.authorization = 'Bearer wrongjwt';
    expressdecodejwt()(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      done();
    });
  });

  it('should throw if jwt is an invalid json', function (done) {
    req.headers = {};
    req.headers.authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.yJ1c2VybmFtZSI6InNhZ3VpYXIiLCJpYXQiOjE0NzEwMTg2MzUsImV4cCI6MTQ3MzYxMDYzNX0.foo';
    expressdecodejwt()(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      done();
    });
  });

  it('should use errors thrown from custom getToken function', function (done) {
    expressdecodejwt({
      getToken: () => { throw new UnauthorizedError('invalid_token', { message: 'Invalid token!' }); }
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, 'Invalid token!');
      done();
    });
  });

});

describe('work tests', function () {
  let req: Request;
  let res: express.Response;

  this.beforeEach(() => {
    req = {} as Request;
    res = {} as express.Response;
  });

  it('should work if options not sent', function () {
    expressdecodejwt();
    assert.ok(true, 'no exception thrown')
  });

  it('should work if authorization header is not valid jwt', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work if authorization header is valid jwt', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work regardless of audience', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', aud: 'expected-audience' }, secret, { expiresIn: 500 });
    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work regardless of token expiry', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', exp: 1382412921 }, secret);
    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work regardless of token issuer', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work regardless of wrong signature', function (done) {
    console.log(req);
    const secret = "shhh";
    const token = jwt.sign({ foo: 'bar1', iss: 'http://www' }, secret);
    // manipulate the token
    const newContent = Buffer
      .from('{"foo": "bar", "edg": "ar"}')
      .toString('base64')
      .replace(/=/g, '');
    const splitetToken = token.split(".");
    splitetToken[1] = newContent;
    const newToken = splitetToken.join(".");
    console.log(newToken);
    // build request
    // @ts-ignore
    req.headers = [];
    req.headers.authorization = 'Bearer ' + newToken;
    expressdecodejwt()(req, res, function () {
      console.log(req.auth);
      assert.equal(req.auth?.foo, 'bar');
      assert.equal(req.auth?.edg, 'ar');
      done();
    });
  });

  it('should work with custom and nested request property', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    const req = {} as Request;
    const res = {} as express.Response;
    const requestProperty = 'auth.payload';

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt({ requestProperty })(req, res, function () {
      assert.equal(req.auth?.payload.foo, 'bar');
      done();
    });
  });

  it('should work if authorization header is valid with a buffer secret', function (done) {
    const secret = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64');
    const token = jwt.sign({ foo: 'bar' }, secret);
    const req = {} as Request;
    const res = {} as express.Response;

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work if Authorization header is capitalized (lambda environment)', function (done) {
    const secret = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64');
    const token = jwt.sign({ foo: 'bar' }, secret);
    const req = {} as Request;
    const res = {} as express.Response;

    req.headers = {};
    req.headers.Authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function (err) {
      if (err) { return done(err); }
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work if no authorization header and credentials are not required', function (done) {
    const req = {} as express.Request;
    const res = {} as express.Response;
    expressdecodejwt({ credentialsRequired: false })(req, res, done);
  });

  it('should not work if no authorization header', function (done) {
    const req = {} as express.Request;
    const res = {} as express.Response;
    expressdecodejwt()(req, res, function (err) {
      assert(typeof err !== 'undefined');
      done();
    });
  });

  it('should work with a custom getToken function', function (done) {
    const req = {} as Request;
    const res = {} as express.Response;
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);

    req.headers = {};
    req.query = {};
    req.query.token = token;

    function getTokenFromQuery(req) {
      return req.query.token;
    }

    expressdecodejwt({ getToken: getTokenFromQuery })(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });

  it('should work with an async getToken function', function (done) {
    const req = {} as Request;
    const res = {} as express.Response;
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);

    req.headers = {};
    req.query = {};
    req.query.token = token;

    function getTokenFromQuery(req) {
      return Promise.resolve(req.query.token);
    }

    expressdecodejwt({ getToken: getTokenFromQuery })(req, res, function () {
      assert.equal(req.auth?.foo, 'bar');
      done();
    });
  });
});
