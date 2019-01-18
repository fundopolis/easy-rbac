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
        const rbac = roleManager();
      },
      TypeError
    );
  });

  it('should throw error if no roles object', () => {
    assert.throws(
      () => {
        const rbac = roleManager('hello');
      },
      TypeError
    );
  });

  it('should return middleware function', () => {
    const rbac = roleManager(data.all);
    assert.equal(typeof rbac, 'function');
  });

  it('should put rbac into request', () => {
    const rbac = roleManager(data.all);
    let req = mock.mockReq(), res = mock.mockRes(), next = function(){};
    rbac(req, res, next);
    assert.notEqual(req.rbac, undefined);
  });

  describe('enforce can parameter constraints', function() {
    it('should should reject undefined operation', () => {
      assert.throws(
        () => {
          RBAC.can();
        },
        TypeError
      );
    });
    it('should accept operation string', () => {
      assert.doesNotThrow(
        () => {
          RBAC.can('role', 'operation');
        }
      );
    });
  });

  it('should allow static role', done => {
    const rbac = RBAC.main(data.all);
    let req = mock.mockReq(), 
      res = mock.mockRes(), 
      next = function(){};
    rbac(req, res, next);
    const can = RBAC.can('user', 'account:add');
    can(req, res, done);
  });

  it('should allow role returned by function', done => {
    const rbac = RBAC.main(data.all);
    let req = mock.mockReq(),
      res = mock.mockRes();
    const next = function(){};
    rbac(req, res, next);
    const can = RBAC.can(function(){return 'user'}, 'account:add');
    can(req, res, done);
  });

  it('should allow role returned by function with request', done => {
    const rbac = RBAC.main(data.all);
    let request = {
      role: 'user'
    };
    let req = mock.mockReq(request),
      res = mock.mockRes();
    const next = function(){};
    rbac(req, res, next);
    const can = RBAC.can(function(req,res){return req.role}, 'account:add');
    can(req, res, done);
  });

  it('should return 403 on unallowed operation', () => {
    const rbac = RBAC.main(data.all);
    let req = mock.mockReq(),
      res = mock.mockRes();
    const next = function(){};
    rbac(req, res, next);
    const can = RBAC.can('user', 'foo_op');
    can(req, res, next);
    assert(res.sendStatus.calledWith(403));
  });  

  
});