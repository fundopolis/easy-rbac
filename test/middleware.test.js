'use strict';

const mock = require('sinon-express-mock');
const sinon = require('sinon');
const rbacMw = require('../lib/middleware');
let data = require('./data');

const assert = require('assert');
const {shouldBeAllowed, shouldNotBeAllowed, catchError} = require('./utils');

describe('RBAC middleware', function() {
  it('should reject if no roles object', () => {
    assert.throws(
      () => {
        rbacMw();
      },
      TypeError
    );
  });

  it('should throw error if roles improperly defined', () => {
    assert.throws(
      () => {
        rbacMw('hello');
      },
      TypeError
    );
  });

  it('should return middleware function', () => {
    const mw = rbacMw(null, null, null, data.all);
    assert.equal(typeof mw, 'function');
  });

  

  // describe('enforce can parameter constraints', function() {
  //   it('should should reject undefined operation', () => {
  //     assert.throws(
  //       () => {
  //         RBAC.can();
  //       },
  //       TypeError
  //     );
  //   });
  //   it('should accept operation string', () => {
  //     assert.doesNotThrow(
  //       () => {
  //         RBAC.can('role', 'operation');
  //       }
  //     );
  //   });
  // });

  it('should allow static role', done => {
    const mw = rbacMw('user', 'account:add', null, data.all);
    let req = mock.mockReq(), 
      res = mock.mockRes(), 
      next = function(err){
        assert.strictEqual(err, undefined);
        done();
      };
    mw(req, res, next);
  });

  it('should reject static role', done => {
    const mw = rbacMw('foo', 'account:add', null, data.all);
    let req = mock.mockReq(), 
      res = mock.mockRes(), 
      next = function(err){
        assert.strictEqual(err instanceof Error, true);
        assert.strictEqual(err.message, 'forbidden');
        done();
      };
    mw(req, res, next);
  });

  it('should allow role returned by function', done => {
    const role = function role() { return 'user' };
    let req = mock.mockReq(),
      res = mock.mockRes();
    const next = function(err){
      assert.equal(err, undefined);
      done();
    };
    const mw = rbacMw(role, 'account:add', null, data.all);
    mw(req, res, next);
  });

  // it('should allow role returned by function with request', done => {
  //   const rbac = RBAC.main(data.all);
  //   let request = {
  //     role: 'user'
  //   };
  //   let req = mock.mockReq(request),
  //     res = mock.mockRes();
  //   const next = function(){};
  //   rbac(req, res, next);
  //   const can = RBAC.can(function(req,res){return req.role}, 'account:add');
  //   can(req, res, done);
  // });

  // it('should return 403 on unallowed operation', () => {
  //   const rbac = RBAC.main(data.all);
  //   let req = mock.mockReq(),
  //     res = mock.mockRes();
  //   const next = function(){};
  //   rbac(req, res, next);
  //   const can = RBAC.can('user', 'foo_op');
  //   can(req, res, next);
  //   assert(res.sendStatus.calledWith(403));
  // });  

  
});