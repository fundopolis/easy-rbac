'use strict';

const RBAC = require('./rbac');

/**
 * Middleware main
 * @param {*} role An object or a function (which can optionally accept request,response)
 * @param {*} operation An object or a function (which can optionally accept request,response)
 * @param {*} params An object or a function (which can optionally accept request,response)
 * @param {*} config Roles configuration as accepted by RBAC
 */
const easyRbacMw = function easyRbacMw(role, operation, params, config) {
    // TODO async initialization?
  const rbac = new RBAC(config);

  return function checkRoleCan(req, res, next) {
    let $role = typeof role === 'function' ? role(req, res) : Promise.resolve(role);
    let $operation = typeof operation === 'function' ? operation(req, res) : Promise.resolve(operation);
    let $params = typeof params === 'function' ? params(req, res) : Promise.resolve(params);

    const handleGrant = (granted) => {
        if (granted) {
            next();
        } else {
            next(new Error('forbidden'));
        }
    };

    const handleError = (err) => {
        console.debug('RBAC.can rejected on error: '+err.message);
        next(err); 
    };

    Promise.all([$role, $operation, $params])
    .then(([role, operation, params]) => rbac.can(role, operation, params))
    .then(handleGrant, handleError);
  }
};

module.exports = easyRbacMw;