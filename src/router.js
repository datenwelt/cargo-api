/* eslint-disable class-methods-use-this */

const bluebird = require('bluebird');
const JWT = bluebird.promisifyAll(require('jsonwebtoken'));
const VError = require('verror');

class Router {

	init(config, state) {
		state = state || {};
		state.routers = state.routers || [];
		state.routers.push(this);
	}

	static asyncRouter(router) {
		return function (req, res, next) {
			const result = router(req, res, next);
			if (result.then && result.catch) {
				return result.catch(next);
			}
			return result;
		};
	}

	static requiresToken(rsaPublicKey) {
		return this.asyncRouter(async function (req, res, next) {
			const authHeader = req.get('Authorization');
			if (!authHeader) {
				res.set('X-Cargo-Error', 'ERR_MISSING_AUTHORIZATION_HEADER')
					.set('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				throw new VError('ERR_MISSING_AUTHORIZATION_HEADER');
			}
			let [authType, authToken] = authHeader.split(/\s+/);
			if (!authType || authType.toLowerCase() !== 'bearer') {
				res.set('X-Cargo-Error', 'ERR_AUTHORIZATION_TYPE_NOT_SUPPORTED')
					.set('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				throw new Error('ERR_AUTHORIZATION_TYPE_NOT_SUPPORTED');
			}
			authToken = (authToken || "").trim();
			if (!authToken) {
				res.set('X-Cargo-Error', 'ERR_MISSING_AUTHORIZATION_TOKEN')
					.set('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);

				throw new Error('ERR_MISSING_AUTHORIZATION_TOKEN');
			}
			let payload = null;
			try {
				payload = await JWT.verifyAsync(authToken, rsaPublicKey);
			} catch (err) {
				if (err.name === 'JsonWebTokenError') {
					res.status(403).set('X-Cargo-Error', 'ERR_INVALID_AUTHORIZATION_TOKEN');
					throw new Error('ERR_INVALID_AUTHORIZATION_TOKEN');
				}
				if (err.name === 'TokenExpiredError') {
					res.status(409).set('X-Cargo-Error', 'ERR_EXPIRED_AUTHORIZATION_TOKEN');
					throw new Error('ERR_EXPIRED_AUTHORIZATION_TOKEN');
				}
				throw new VError(err, 'Error validating token');
			}
			req.sessionId = payload.sess;
			if (payload.usr) {
				if (payload.usr.id) req.userId = payload.usr.id;
				if (payload.usr.nam) req.username = payload.usr.nam;
			}
			req.token = payload;
			return next();
		});
	}


}

module.exports = Router;
