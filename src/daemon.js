/* eslint-disable class-methods-use-this,no-unused-vars,no-process-exit,func-style */
// eslint-disable-next-line id-length
const _ = require('underscore');
const ms = require('ms');
const VError = require('verror');

class Daemon {

	constructor(name, options) {
		options = Object.assign({
			dieOnInitFail: false,
			shutdownGracePeriod: '10s',
			logger: console
		}, options || {});
		this.options = options;
		if (!name) {
			throw new VError('Missing param #1 (name) in constructor call.');
		}
		this.name = name;
		if ( this.options.logger ) {
			this.log_error = this.options.logger.error.bind(this.options.logger);
			this.log_debug = this.options.logger.debug.bind(this.options.logger);
			this.log_info = this.options.logger.info.bind(this.options.logger);
			this.log_warn = this.options.logger.warn.bind(this.options.logger);
		} else {
			this.log_error = function() {};
			this.log_info = function() {};
			this.log_warn = function() {};
		}
		Object.assign(this, options);
	}

	clone() {
		const options = Object.assign({}, this.options);
		return new Daemon(this, options);
	}

	async run() {
		try {
			if (!this.isClone) {
				this.config = await this.init();
			}
		} catch (err) {
			throw new VError(err, 'Init process failed for server [%s]', this.name);
		}

		this.handleSigint = function () {
			process.removeListener('SIGINT', this.handleSigint);
			process.removeListener('SIGHUP', this.handleSighup);

			this.log_info('[%s] Shutting down server.', this.name);
			let graceTimeout = setTimeout(function () {
				this.log_info('Shutdown of server did not finish within grace period (%s). Terminating.', this.shutdownGracePeriod);
				process.exit(0);
			}.bind(this), ms(this.shutdownGracePeriod));
			this.shutdown().then(function () {
				clearTimeout(graceTimeout);
				process.exit(0);
			}).catch(function (err) {
				this.log_error('Shutdown failed. Terminating: %s', err.message);
				this.log_debug(VError.fullStack(err));
				process.exit(1);
			}.bind(this));
		}.bind(this);

		this.handleSighup = function () {

			process.removeListener('SIGINT', this.handleSigint);
			process.removeListener('SIGHUP', this.handleSighup);

			const newInstance = this.clone();
			newInstance.isClone = true;

			const startServer = function () {
				this.log_info('Starting new server instance on reload event');
				newInstance.run().then(function () {
					this.log_info('Reload completed successfully.');
				}.bind(this)).catch(function (err) {
					this.log_error('Reload failed: ' + err.message);
					this.log_debug(VError.fullStack(err));
				}.bind(this));
			}.bind(this);

			const shutdownServer = function () {
				this.log_info('Shutting down old server instance on reload event.');
				let graceTimeout = setTimeout(function () {
					this.log_warn('Shutdown did not finish within grace period (%s).', this.shutdownGracePeriod);
					if (this.dieOnInitFail) {
						process.exit(1);
						return;
					}
					startServer();
				}.bind(this), ms(this.shutdownGracePeriod));
				this.shutdown().then(function () {
					clearTimeout(graceTimeout);
					startServer();
				}).catch(function (err) {
					clearTimeout(graceTimeout);
					this.log_error('Server shutdown failed: ' + err.message);
					this.log_debug(VError.fullStack(err));
					if (this.dieOnInitFail) {
						process.exit(1);
					} else {
						startServer();
					}
				}.bind(this));
			}.bind(this);

			this.log_info('Reload initiated by SIGHUP.');
			this.log_info('Initializing new server instance before shutdown of old instance.');
			newInstance.init().then(function (config) {
				newInstance.config = config;
				shutdownServer();
			}).catch(function (err) {
				this.log_error('Unable to initialitze new server instance: ' + err.message);
				this.log_debug(err);
				if (this.dieOnInitFail) {
					this.log_error('Terminatig.');
					process.exit(1);
				} else {
					shutdownServer();
				}
			}.bind(this));
		}.bind(this);

		process.on('SIGINT', this.handleSigint);
		process.on('SIGHUP', this.handleSighup);

		await this.startup();
	}

	async init() {
	}

	async startup() {
	}

	async shutdown() {
	}

	async reload() {
		await this.handleSighup();
	}

}

module.exports = Daemon;
