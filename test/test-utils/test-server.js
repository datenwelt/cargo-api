const bodyParser = require('body-parser');
const express = require('express');
const Promise = require('bluebird');
const URI = require('urijs');

module.exports = {

	start: function () {
		return new Promise(function (resolve, reject) {
			const app = express();
			app.on('error', function (err) {
				app.removeAllListeners('error');
				app.removeAllListeners('listening');
				reject(err);
			});
			app.listen(function () {
				// eslint-disable-next-line no-invalid-this
				app.server = this;
				let uri = new URI('http://127.0.0.1/');
				uri.port(app.server.address().port);
				app.uri = uri;
				app.removeAllListeners('error');
				app.removeAllListeners('listening');
				resolve(app);
			});
			app.use(bodyParser.json());
		});

	}

};

