'use strict';

var ActiveDirectory = require('activedirectory');
var htpasswdPlugin = require('verdaccio-htpasswd');

function Plugin(config, stuff) {
	var self = Object.create(Plugin.prototype);
	self._config = config;
	self._logger = stuff.logger;
  self._logger.info('Active Directory plugin configuration:\n', config);
  
  self._config.username = config.user + '@' + config.domainSuffix;

  /**
   * This AD auth plugin modification uses 2 strategies:
   * Primary one is AD and backup one is htpasswd
   * htpasswd strategy relies on 'extendedUsersFile' config option
   */
  if (config.extendedUsersFile) {
    self._htpasswdPlugin = htpasswdPlugin.default({
      file: config.extendedUsersFile
    }, stuff);
  }

  /**
   * Default group and suffix value for htpasswd users is OUTSOURCE
   */
	self._extendedUsersSuffix = self._config.extendedUsersSuffix;
	if (!self._extendedUsersSuffix) {
		self._extendedUsersSuffix = 'OUTSOURCE';
  }
  
  /**
   * Connection to AD is being created once
   */
  self._connection = new ActiveDirectory(self._config);
  self._connection.on('error', function(error) {
		if (
			!self._htpasswdPlugin ||
			error.toString().indexOf('InvalidCredentialsError') < 0
		) {
			self._logger.warn('Active Directory connection error. Error:', error);
		}
  });

	return self;
}

/**
 * Authentication is allowed via AD or htpasswd either
 */
Plugin.prototype.authenticate = function(user, password, callback) {
  var self = this;
	var username = user + '@' + self._config.domainSuffix;

	var processAuthenticated = function(authenticated, method, group) {
		if (!authenticated) {
			var message = '' + method + ' authentication failed';
			self._logger.warn(message);
			return callback(new Error(message));
		}

		self._logger.info('' + method + ' authentication succeeded')
		callback(null, [user, group]);
	};

	var authenticateViaHtpasswd = function() {
		var cb = function (hErr, hAuthenticated) {
			if (hErr) {
				self._logger.warn('htpasswd authentication failed. Error code:', hErr.code + '.', 'Error:\n', hErr);
				return callback(hErr);
			} else {
				return processAuthenticated(
					hAuthenticated,
					'htpasswd',
					self._extendedUsersSuffix
				);
			}
		};
		var username = self._getHtpasswdUsername(user);
		return self._htpasswdPlugin.authenticate(username, password, cb);
	};
  
  /**
   * If the user exists in AD, we do not try authenticating him with htpasswd
   */
  self._connection.userExists(user, function(err, exists) {
    if (err) {
      self._logger.warn('Active Directory user existance check failed. Error code:', err.code + '.', 'Error:\n', err);
      return callback(err);
    }
    if (exists) {
      self._connection.authenticate(username, password, function(err, authenticated) {
        if (err) {
          self._logger.warn('Active Directory authentication failed. Error code:', err.code + '.', 'Error:\n', err);
          return callback(err);
        } else {
          return processAuthenticated(
            authenticated,
            'Active Directory',
            '$ActiveDirectory'
          );
        }
      });
    } else if (self._htpasswdPlugin) {
      self._logger.warn('Active Directory authentication failed. Trying htpasswd authentication...');
      return authenticateViaHtpasswd();
    }
  });
};

Plugin.prototype._getHtpasswdUsername = function(user) {
	return user + '__' + this._extendedUsersSuffix;
};

/**
 * Registration is allowed if htpasswd strategy is on
 */
Plugin.prototype.adduser = function(user, password, callback) {
  var self = this;
  
  /** 
   * Stop adduser if username already exists in AD
   */
  self._connection.userExists(user, function(err, exists) {
    if (err) {
      self._logger.warn('Active Directory user existance check failed. Error code:', err.code + '.', 'Error:\n', err);
      return callback(err);
    }
    if (exists) {
      self._logger.info('Active Directory user exists. adduser skipped');
      return callback(null, false);
    }

    if (!self._htpasswdPlugin) {
      var message = 'No extendedUsersFile provided in config. Registration is forbidden';
      self._logger.warn(message);
      return callback(new Error(message));
    }
  
    var username = self._getHtpasswdUsername(user);
    self._logger.info('Creating user ' + username + ' with htpasswd strategy');
    return self._htpasswdPlugin.adduser(username, password, callback);
  });
};

module.exports = Plugin;