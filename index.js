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
	
	var connection = new ActiveDirectory(_.extend(this._config, { username: username, password: password }));
	connection.on('error', function(error) {
		self._logger.warn('Active Directory connection error. Error:', error);
	});

	/**
	 * Authentication is allowed via AD or htpasswd either
	 */
	connection.authenticate(username, password, function(err, authenticated) {
		if (err) {
			self._logger.warn('Active Directory authentication failed. Error code:', err.code + '.', 'Error:\n', err);
			if (self._config.extendedUsersFile) {
				self._logger.info('Trying htpasswd authentication...');
				self._authenticateViaHtpasswd(user, password, function (hErr, hAuthenticated) {
					if (hErr) {
						self._logger.warn('htpasswd authentication failed. Error code:', hErr.code + '.', 'Error:\n', hErr);
						return callback(hErr);
					}
				});
			}
			return callback(err);      
		}

		if (!authenticated) {
			var message = 'Active Directory authentication failed';
			self._logger.warn(message);
			return callback(new Error(message));
		}

		self._logger.info('Active Directory authentication succeeded')
		callback(null, [user]);
	});
};

Plugin.prototype._authenticateViaHtpasswd = function(user, password, callback) {
	var username = this._getHtpasswdUsername(user);
	self._htpasswdPlugin.authenticate(username, password, callback);
};

Plugin.prototype._adduserViaHtpasswd = function(user, password, callback) {
	var username = this._getHtpasswdUsername(user);
	self._htpasswdPlugin.adduser(username, password, callback);
};

Plugin.prototype._getHtpasswdUsername = function(user) {
	var extendedUsersSuffix = this._config.extendedUsersSuffix;
	if (!extendedUsersSuffix) {
		extendedUsersSuffix = 'OUTSOURCE';
	}
	return user + '@' + extendedUsersSuffix;
}

/**
 * Registration is allowed
 * if the extendedUsersFile paramter is provided in plugin's config
 */
Plugin.prototype.adduser = function(user, password, callback) {
	var self = this;
	
	if (!this._config.extendedUsersFile) {
		var message = 'No extendedUsersFile provided in config. Registration is forbidden';
		self._logger.warn(message);
		return callback(new Error(message));
	}

	this._adduserViaHtpasswd(user, password, callback);
};

module.exports = Plugin;