const amqp = require('amqplib');
const VError = require('verror');

class MQ {

	constructor() {
		this.connection = null;
		this.channel = null;
		this.exchange = null;
		this.uri = null;
		this.options = {};
	}

	async init(config, options) {
		config = config || {};
		const uri = config.uri;
		const exchange = config.exchange;
		options = Object.assign(config.options || {}, options);

		if (!uri) throw new VError('Missing "uri" value in MQ configuration.');
		if (!exchange) throw new VError('Missing "exchange" value in MQ configuration.');

		const connection = await amqp.connect(uri, options);
		const channel = await connection.createChannel();
		await channel.assertExchange(exchange, 'topic', {durable: true});

		this.uri = uri;
		this.exchange = exchange;
		this.connection = connection;
		this.channel = channel;
		this.options = options;

		this.channel.on('error', function () {
			this.channel = null;
		}.bind(this));

		this.channel.on('close', function () {
			this.channel = null;
		}.bind(this));

		this.connection.on('error', function () {
			this.connection = null;
		}.bind(this));

		this.connection.on('close', function () {
			this.connection = null;
		}.bind(this));

		return this;
	}

	async connect() {
		if (this.connection) return this.connection;
		this.connection = await amqp.connect(this.uri, this.options);
		return this.connection;
	}

	async connectChannel() {
		if (this.channel) return this.channel;
		const connection = await this.connect();
		return connection.createChannel();
	}

	async close() {
		if (this.channel) {
			try {
				await this.channel.close();
			// eslint-disable-next-line no-empty
			} catch (err) {
			}
			this.channel = null;
		}
		if (this.connection) {
			try {
				await this.connection.close();
			// eslint-disable-next-line no-empty
			} catch (err) {
			}
			this.connection = null;
		}

	}

}

module.exports = MQ;
