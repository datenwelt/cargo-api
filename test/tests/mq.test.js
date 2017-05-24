/* eslint-disable no-invalid-this,consistent-return */
const describe = require('mocha').describe;
const before = require('mocha').before;
const it = require("mocha").it;
const assert = require('chai').assert;

const TestConfig = require('../test-utils/test-config');
const TestMQ = require('../test-utils/test-mq');
const MQ = require('../../src/mq');

let mq = null;
let config = null;

describe('mq.js', function() {

	before(async function() {
		config = await TestConfig.get();
		mq = await TestMQ.get();
	});

	describe('static init()', function() {

		it('connects to an RabbitMQ server and creates an exchange.', async function() {
			if ( !mq ) return this.skip();
			const testMq = await new MQ().init(config.mq);
			const connection = await testMq.connect();
			assert.isDefined(connection);
			const channel = await connection.createChannel();
			await channel.checkExchange('cargo');
		});

	});

});

