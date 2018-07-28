'use strict';

var ActiveDirectory = require('activedirectory');
var _ = require('lodash');
var htpasswdPlugin = require('verdaccio-htpasswd');

function Plugin(config, stuff) {
	var self = Object.create(Plugin.prototype);
	self._config = config;
	self._logger = stuff.logger;
	self._logger.info('Active Directory plugin configuration:\n', config);
	self._htpasswdPlugin = htpasswdPlugin.default({
		file: config.extendedUsersFile
	}, stuff);
	return self;
}

Plugin.prototype.authenticate = function(user, password, callback) {
	var self = this;
	var username = user + '@' + this._config.domainSuffix;

	var processAuthenticated = function(authenticated, method) {
		if (!authenticated) {
			var message = '' + method + ' authentication failed';
			self._logger.warn(message);
			return callback(new Error(message));
		}

		self._logger.info('' + method + ' authentication succeeded')
		callback(null, [user]);
	};

	var authenticateViaHtpasswd = function() {
		var cb = function (hErr, hAuthenticated) {
			if (hErr) {
				self._logger.warn('htpasswd authentication failed. Error code:', hErr.code + '.', 'Error:\n', hErr);
				return callback(hErr);
			} else {
				return processAuthenticated(
					hAuthenticated,
					'htpasswd'
				);
			}
		};
		var username = self._getHtpasswdUsername(user);
		return self._htpasswdPlugin.authenticate(username, password, cb);
	};
	
	var connection = new ActiveDirectory(_.extend(this._config, { username: username, password: password }));
	connection.on('error', function(error) {
		if (
			!self._config.extendedUsersFile ||
			error.toString().indexOf('InvalidCredentialsError') < 0
		) {
			self._logger.warn('Active Directory connection error. Error:', error);
		}
	});

	/**
	 * Authentication is allowed via AD or htpasswd either
	 */
	connection.authenticate(username, password, function(err, authenticated) {
		if (err) {
			if (self._config.extendedUsersFile) {
				self._logger.warn('Active Directory authentication failed. Trying htpasswd authentication...');
				return authenticateViaHtpasswd();
			} else {
				self._logger.warn('Active Directory authentication failed. Error code:', err.code + '.', 'Error:\n', err);
				return callback(err);
			}
		} else {
			return processAuthenticated(
				authenticated,
				'Active Directory'
			);
		}
	});
};

Plugin.prototype._getHtpasswdUsername = function(user) {
	var extendedUsersSuffix = this._config.extendedUsersSuffix;
	if (!extendedUsersSuffix) {
		extendedUsersSuffix = 'OUTSOURCE';
	}
	return user + '__' + extendedUsersSuffix;
};

/**
 * Registration is allowed
 * if the extendedUsersFile paramter is provided in plugin's config
 */
Plugin.prototype.adduser = function(user, password, callback) {
	var self = this;
	
	if (!self._config.extendedUsersFile) {
		var message = 'No extendedUsersFile provided in config. Registration is forbidden';
		self._logger.warn(message);
		return callback(new Error(message));
	}

	var username = self._getHtpasswdUsername(user);
	return self._htpasswdPlugin.adduser(username, password, callback);
};

module.exports = Plugin;