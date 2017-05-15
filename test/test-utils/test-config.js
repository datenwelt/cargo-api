/* eslint-disable no-sync,no-process-env */
const bluebird = require('bluebird');
const fs = bluebird.promisifyAll(require('fs'));
const toml = require('toml');

let config = null;

class TestConfig {

	static async get() {
		if ( config ) return config;
		const data = await fs.readFileAsync(process.env.CARGO_AUTH_CONFIG || 'test/examples/test-config.toml', 'utf8');
		config = toml.parse(data);
		return config;
	}

}

module.exports = TestConfig;
