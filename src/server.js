/* eslint-disable id-length,class-methods-use-this */
const _ = require('underscore');
const bunyan = require('bunyan');
const crypto = require('crypto');
const moment = require('moment');
const os = require('os');
const Promise = require('bluebird');
const VError = require('verror');

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const Config = require('./config');
const Daemon = require('./daemon');
const MQ = require('./mq');

class HttpServer extends Daemon {
	
	constructor(name, configFile, options) {
		super(name, options);
		if (!configFile) {
			throw new VError('Missing parameter #2 (configFile) in constructor call.');
		}
		this.configFile = configFile;
		this.routers = [];
		this.mq = null;
		this.appLogger = null;
	}
	
	clone() {
		return new HttpServer(this.name, this.configFile, this.options);
	}
	
	async init() {
		const config = await Config.load(this.configFile);
		const state = {};
		
		// Application logger
		if (config.logs && config.logs.logfile) {
			const logfile = config.logs.logfile;
			const level = config.logs.level || 'INFO';
			try {
				this.appLogger = bunyan.createLogger({
					name: this.name,
					streams: [{path: logfile, type: 'file'}],
					level: level
				});
			} catch (err) {
				throw new VError(err, "Unable to initialize application log at %s", logfile);
			}
		}
		
		// MQ connection
		if (config.mq) {
			try {
				this.mq = await new MQ().init(config.mq);
			} catch (err) {
				throw new VError(err, "Unable to connect to message queue at %s", config.uri);
			}
		}
		
		
		let port = Number.parseInt(config.server.port || 80, 10);
		if (Number.isNaN(port) || port <= 0) {
			throw new VError('Invalid value for "server.port": %s', config.server.port);
		}
		this.listen = {port: port, address: config.server.address || "127.0.0.1"};
		
		this.app = express();
		
		this.app.use(function (req, res, next) {
			const md5 = crypto.createHash('MD5');
			md5.update(Math.random().toString(10));
			req.id = md5.digest('hex').substr(0, 8).toUpperCase();
			res.requestId = req.id;
			next();
		});
		
		
		this.app.use(bodyParser.json());
		this.app.use(cors());
		this.app.options('*', cors());
		
		if (config.server.routes) {
			for (let routeIndex of Object.keys(config.server.routes).sort()) {
				let routeConfig = config.server.routes[routeIndex];
				let route = routeConfig.path;
				let moduleSrc = routeConfig.module;
				let routerName = this.name + ".";
				routerName += routeConfig.name || "router" + routeIndex;
				try {
					if (!route) {
						throw new VError('Missing "path" in configuration for route #%s', routeIndex);
					}
					if (!moduleSrc) {
						throw new VError('Missing "module" in configuration for route #%s', moduleSrc);
					}
					if (!path.isAbsolute(moduleSrc)) {
						moduleSrc = path.join(process.cwd(), moduleSrc);
						moduleSrc = path.normalize(moduleSrc);
					}
					this.log_info('Initializing router for route "%s" from "%s".', route, moduleSrc);
					// eslint-disable-next-line global-require
					let Router = require(moduleSrc);
					let router = new Router(this.name);
					// eslint-disable-next-line no-await-in-loop
					this.app.use(route, await router.init(config, state));
					this.routers.push(router);
					if (this.mq) router.onAny(this.createMqDispatcher(routerName));
					if (this.appLogger) router.onAny(this.createApplogDispatcher());
				} catch (err) {
					this.log_error(err, 'Unable to initialize router for route "%s" from module "%s". Skipping this route.', route, moduleSrc);
				}
			}
		}
		if (config.server && config.server.fail_without_routes) {
			if (!this.routers || !this.routers.length) {
				throw new VError('Server has no routes. Use config setting "server.fail_without_routes=false" to start anyways.');
			}
		}
		
		this.app.all('*', function (req, res, next) {
				if (!res.headersSent) res.sendStatus(404);
				next();
			}
		);
		
		// Error log
		if (config.server && config.server.error_log) {
			let logfile = config.server.error_log;
			try {
				this.app.use(HttpServer.createErrorLog(logfile));
			} catch (err) {
				throw new VError(err, "Unable to initialize error.log at %s", logfile);
			}
		}
		
		// General error handler.
		// eslint-disable-next-line handle-callback-err,max-params
		this.app.use(HttpServer.createStandardErrorHandler());
		
		// Access Log
		if (config.server && config.server.access_log) {
			let logfile = config.server.access_log;
			try {
				this.app.use(HttpServer.createAccessLog(logfile));
			} catch (err) {
				throw new VError(err, "Unable to initialize access.log at %s", logfile);
			}
		}
		
		return config;
	}
	
	startup() {
		return new Promise(function (resolve, reject) {
			const app = this.app;
			const port = this.listen.port;
			const addr = this.listen.address;
			let errorListener = app.on('error', function (err) {
				app.removeListener('error', errorListener);
				reject(new VError(err, "Error listening on %s:%s", addr, port));
			});
			let listenReady = function (server) {
				app.server = server;
				this.log_info('Server listening on %s:%d', addr, port);
				app.removeListener('error', errorListener);
			}.bind(this);
			app.listen(port, addr, function () {
				// eslint-disable-next-line no-invalid-this
				listenReady(this);
				resolve();
			});
			
		}.bind(this));
	}
	
	shutdown() {
		return new Promise(function (resolve) {
			if (this.app && this.app.server) {
				this.app.server.close(async function () {
					if (this.routers) {
						for (let router of this.routers) {
							// eslint-disable-next-line no-await-in-loop
							await router.shutdown();
						}
					}
				}.bind(this));
			}
			if (this.mq) this.mq.close();
			resolve();
		}.bind(this));
	}
	
	static createStandardErrorHandler(headerName) {
		headerName = headerName || 'X-Error';
		// eslint-disable-next-line max-params
		return function (err, req, res, next) {
			if (err.name === 'HttpError') res.set(headerName, err.message).sendStatus(err.code);
			else res.sendStatus(500);
			next(err);
		};
	}
	
	static createAccessLog(logfile) {
		const logger = bunyan.createLogger({
			name: "access",
			streams: [{level: 'INFO', path: logfile}]
		});
		return function (req, res, next) {
			const logContent = {};
			logContent.client = req.ip;
			logContent.requestId = req.id;
			logContent.username = req.username || '-';
			logContent.date = req.get('Date');
			logContent.method = req.method;
			logContent.url = req.originalUrl;
			logContent.status = res.statusCode;
			const cargoError = res.get('X-Error') || "";
			logger.info(logContent, cargoError);
			next();
		};
		
	}
	
	static createErrorLog(logfile) {
		const logger = bunyan.createLogger({
			name: "error",
			streams: [{level: 'DEBUG', path: logfile}]
		});
		// eslint-disable-next-line max-params
		return function (err, req, res, next) {
			if (res.statusCode === 500)
				logger.error({requestId: req.id, err: err});
			next(err);
		};
	}
	
	createMqDispatcher(name) {
		return async function (event, data) {
			if (event !== 'error') {
				let channel = null;
				try {
					channel = await this.mq.connectChannel();
				} catch (err) {
					this.log_error(err, 'Unable to connect to message queue at %s', this.mq.uri);
					this.log_info('Shutting down after fatal error.');
					await this.shutdown();
					// eslint-disable-next-line no-process-exit
					process.exit(1);
					return;
				}
				try {
					// eslint-disable-next-line no-undefined
					const json = JSON.stringify(data || {}, undefined, ' ');
					const content = Buffer.from(json, 'utf8');
					const routingKey = name + "." + event;
					channel.publish(this.mq.exchange, routingKey, content, {
						persistent: true,
						contentType: 'application/json',
						timestamp: moment().unix(),
						appId: this.name + '@' + os.hostname()
					});
				} catch (err) {
					this.log_error(err, "Unable publish API event '%s' to message qeue: %s", event, err.message);
				}
			}
		}.bind(this);
	}
	
	createApplogDispatcher() {
		return function (event, ...args) {
			if (event === 'error') {
				if (args[0] && args[0] instanceof Error) {
					this.appLogger.error(args[0].message);
					this.appLogger.debug(...args);
				} else {
					this.appLogger.error(...args);
				}
			} else {
				this.appLogger.info(...args);
			}
		}.bind(this);
	}
	
}

module.exports = HttpServer;
