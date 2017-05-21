const Promise = require('bluebird');
const fs = Promise.promisifyAll(require('fs'));
const toml = require('toml');

class Config {

	static async load(filename) {
		let configContent = await fs.readFileAsync(filename, 'utf8');
		return toml.parse(configContent);
	}

	static find(locations) {
		let configFile = null;
		for (configFile of locations) {
			if (!configFile) continue;
			try {
				// eslint-disable-next-line no-sync
				let stats = fs.statSync(configFile);
				if (!stats || !stats.isFile()) {
					continue;
				}
				// eslint-disable-next-line no-sync
				fs.accessSync(configFile, 'r');
			} catch (err) {
				continue;
			}
			break;
		}
		return configFile;
	}

}

module.exports = Config;
