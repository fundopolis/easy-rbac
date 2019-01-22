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

  it('should pass on error if thrown in roles construction', done => {
    const roleConfig = function(){ throw new Error('foo')};
    const mw = rbacMw(null, null, null, roleConfig);
    let req = mock.mockReq(), 
      res = mock.mockRes(), 
      next = function(err){
        assert.strictEqual(err instanceof Error, true);
        assert.strictEqual(err.message, 'foo');
        done();
      };
    mw(req, res, next);
  });

  it('should return middleware function', () => {
    const mw = rbacMw(null, null, null, data.all);
    assert.equal(typeof mw, 'function');
  });

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

  it('should reject unknown static role', done => {
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

  if('should call role function with request and response objects', done => {
    const role = sinon.stub();
    let req = mock.mockReq(),
      res = mock.mockRes();
    const mw = rbacMw(role, 'account:add', null, data.all);
    mw(req, res, () => {
      assert.strictEqual(role.calledWith(req, res), true);
      done();
    });
  });

  if('should call operation function with request and response objects', done => {
    const operation = sinon.stub();
    let req = mock.mockReq(),
      res = mock.mockRes();
    const mw = rbacMw('role', operation, null, data.all);
    mw(req, res, () => {
      assert.strictEqual(operation.calledWith(req, res), true);
      done();
    });
  });

  if('should call params function with request and response objects', done => {
    const params = sinon.stub();
    let req = mock.mockReq(),
      res = mock.mockRes();
    const mw = rbacMw('role', 'operation', params, data.all);
    mw(req, res, () => {
      assert.strictEqual(params.calledWith(req, res), true);
      done();
    });
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

  it('should reject unknown role returned by function', done => {
    const role = function role() { return 'foo' };
    let req = mock.mockReq(),
      res = mock.mockRes();
    const next = function(err){
      assert.strictEqual(err instanceof Error, true);
      assert.strictEqual(err.message, 'forbidden');
      done();
    };
    const mw = rbacMw(role, 'account:add', null, data.all);
    mw(req, res, next);
  });

  
});