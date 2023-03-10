import * as jwt from 'jsonwebtoken';
import * as express from 'express';
import { expressdecodejwt, ExpressJwtRequest } from '../src';
import * as assert from 'assert';


describe('string tokens', function () {
  const req = {} as ExpressJwtRequest<string>;
  const res = {} as express.Response;

  it('should work with a valid string token', function (done) {
    const secret = 'shhhhhh';
    const token = jwt.sign('foo', secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressdecodejwt()(req, res, function () {
      assert.equal(req.auth, 'foo');
      done();
    });
  });

});
