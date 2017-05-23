/* eslint-disable class-methods-use-this */

const bluebird = require('bluebird');
const JWT = bluebird.promisifyAll(require('jsonwebtoken'));
const VError = require('verror');

class Router {
	
	constructor() {
		this.errorHeader = 'X-Cargo-Error';
	}
	
	init(config, state) {
		state = state || {};
		state.routers = state.routers || [];
		state.routers.push(this);
		if (config.server && config.server.errorHeader) this.errorHeader = config.server.errorHeader;
	}

	shutdown() {}

	static asyncRouter(router) {
		return function (req, res, next) {
			const result = router(req, res, next);
			if (result.then && result.catch) {
				return result.catch(next);
			}
			return result;
		};
	}
	
	requiresAuthentication() {
		return function (req, res, next) {
			if (res.headersSent) return next();
			if (req.username) return next();
			if (!res.get('WWW-Authenticate')) res.set('WWW-Authenticate', "* realm='Authorizazion required.'");
			res.append(this.errorHeader, 'ERR_UNAUTHENTICATED_ACCESS');
			throw new VError(res.get('X-Cargo-Error'));
		}.bind(this);
	}
	
	checkSessionToken(rsaPublicKey) {
		return Router.asyncRouter(async function (req, res, next) {
			if (res.headersSent) return next();
			if (req.username) return next();
			const authHeader = req.get('Authorization');
			if (!authHeader) {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				return next();
			}
			let [authType, authToken] = authHeader.split(/\s+/);
			if (!authType || authType.toLowerCase() !== 'bearer') {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				return next();
			}
			authToken = (authToken || "").trim();
			if (!authToken) {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				return next();
			}
			let payload = null;
			try {
				payload = await JWT.verifyAsync(authToken, rsaPublicKey);
			} catch (err) {
				if (err.name === 'JsonWebTokenError') {
					res.status(403).append(this.errorHeader, 'ERR_INVALID_AUTHORIZATION_TOKEN');
					return next();
				}
				if (err.name === 'TokenExpiredError') {
					res.status(410).append(this.errorHeader, 'ERR_EXPIRED_AUTHORIZATION_TOKEN');
					return next();
				}
				throw new VError(err, 'Error validating token');
			}
			req.sessionId = payload.sess;
			if (payload.usr) {
				if (payload.usr.id) req.userId = payload.usr.id;
				if (payload.usr.nam) req.username = payload.usr.nam;
			}
			req.token = payload;
			res.append('Vary', 'Authorization');
			res.status(200);
			return next();
		}.bind(this));
	}
	
}

module.exports = Router;
