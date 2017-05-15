/* eslint-disable no-console */
const MQ = require('../../src/mq');
const TestConfig = require('./test-config');

let mq = null;
class TestMQ {

	static async get() {
		if ( mq === false ) {
			return false;
		}
		if (mq) return mq;
		const config = await TestConfig.get();
		try {
			mq = await new MQ().init(config.mq);
		} catch (err) {
			console.log(err);
			mq = false;
		}
		return mq;
	}
}

module.exports = TestMQ;
