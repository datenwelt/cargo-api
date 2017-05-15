const Envelope = require('envelope');
const EventEmitter = require('events').EventEmitter;
const Promise = require('bluebird');
const TestConfig = require('./test-config');

const SMTPServer = require('smtp-server').SMTPServer;

let instance = null;

class TestSmtpServer extends EventEmitter {

	constructor(smtpServer) {
		super();
		this.smtpServer = smtpServer;
		this.messages = [];
	}

	waitForMessage(options) {
		options = Object.assign({timeout: 2000}, options || {});
		return new Promise(function (resolve, reject) {
			let waitTimeout = null;
			const msgListener = function (message) {
				if (waitTimeout) clearTimeout(waitTimeout);
				this.removeListener('message', msgListener);
				resolve(message);
			}.bind(this);
			if (options.timeout > 0) {
				waitTimeout = setTimeout(function () {
					this.removeListener('message', msgListener);
					clearTimeout(waitTimeout);
					reject(new Error('Timeout waiting on message from SMTP server.'));
				}.bind(this), options.timeout);
			}
			this.on('message', msgListener);
		}.bind(this));
	}

	static close() {
		if (!instance) return Promise.resolve();
		return new Promise(function (resolve) {
			instance.smtpServer.close(function () {
				resolve();
			});
			instance = null;
		});
	}

	static async get() {
		if (instance) return instance;
		const config = await TestConfig.get();
		if (!config.smtp) throw new Error('Unable to initialize SMTP server: test configuration does not contain "[smtp]" section.');

		instance = new TestSmtpServer();
		let server = new SMTPServer({
			allowInsecureAuth: true,
			disableReverseLookup: true,
			onAuth: function (auth, session, callback) {
				callback(null, {user: auth.username});
			},
			onData: function (stream, session, callback) {
				let data = Buffer.alloc(0);
				stream.on('data', function (chunk) {
					data = Buffer.concat([data, chunk]);
				});
				stream.on('end', function () {
					const message = new Envelope(data);
					instance.emit('message', message);
					instance.messages.push(message);
					callback();
				});
			}
		});
		await new Promise(function (resolve) {
			server.listen(config.smtp.port, function () {
				resolve();
			});
		});

		instance.smtpServer = server;
		return instance;
	}


}

module.exports = TestSmtpServer;
