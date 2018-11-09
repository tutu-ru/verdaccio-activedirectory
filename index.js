'use strict';

var ActiveDirectory = require('activedirectory');
var htpasswdPlugin = require('verdaccio-htpasswd');

var userGroupsCache = {};
var userGroupsCacheTTL = 1000 * 60 * 60 * 24 * 30;

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

	var processAuthenticated = function(authenticated, method, group, getGroups) {
		if (!authenticated) {
			var message = '' + method + ' authentication failed';
			self._logger.warn(message);
			var error = new Error(message);
			error.status = 401;
			return callback(error);
		}

		if (getGroups === undefined) {
			getGroups = true;
		}

		self._logger.info('' + method + ' authentication succeeded')
		if (!getGroups) {
			return callback(null, [user, group]);
		}

		/**
		 * Obtaining user groups from AD
		 */
		var now = +new Date();
		if (
			userGroupsCache &&
			userGroupsCache[user] &&
			userGroupsCache[user]['last_checked'] + userGroupsCacheTTL > now
		) {
			return callback(null, userGroupsCache[user]['groups']);
		} else {
			setTimeout(function() {
        try {
          self._connection.getGroupMembershipForUser(user, function(err, groups) {
            if (err) {
              self._logger.warn('Couldn\'t obtain groups of user ', user, 'Error code:', err.code + '.', 'Error:\n', err);
              return callback(null, [user, group]);
            }

            const groupNames = [user, group].concat(
              groups.map(function(g) {
                return g.cn;
              })
            );
            self._logger.info('Got user groups', groupNames);
            userGroupsCache[user] = { groups: groupNames, last_checked: now };
            callback(null, groupNames);
          });
        } catch (err) {
          self._logger.error('Couldn\'t obtain groups of user ', user, 'Uncaught Exception:\n', err);
          return callback(null, [user, group]);
        }
			}, 500);
		}
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
					self._extendedUsersSuffix,
					false
				);
			}
		};
		var username = self._getHtpasswdUsername(user);
		return self._htpasswdPlugin.authenticate(username, password, cb);
	};

	/**
	 * If the user exists in AD, we do not try authenticating him with htpasswd
	 */
  try {
    self._connection.userExists(user, function(err, exists) {
      if (err) {
        self._logger.warn('Active Directory user existance check failed. Error code:', err.code + '.', 'Error:\n', err);
        return callback(err);
      }
      if (exists) {
        try {
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
        } catch (e) {
          self._logger.error('Active Directory authentication failed. Uncaught exception: ', e);
          e.status = e.status || 500;
          callback(e);
        }
      } else if (self._htpasswdPlugin) {
        self._logger.warn('Active Directory authentication failed. Trying htpasswd authentication...');
        return authenticateViaHtpasswd();
      }
    });
  } catch (err) {
    self._logger.error('Active Directory user existance check failed. Uncaught exception: ', err);
    err.status = err.status || 500;
    callback(err);
  }
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
	 * Invalidating user groups cache for user that relogins
	 */
	userGroupsCache[user] = {};

	/**
	 * Stop adduser if username already exists in AD
	 */
  try {
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
        var error = new Error(message);
        error.status = 409;
        return callback(error);
      }

      var username = self._getHtpasswdUsername(user);
      self._logger.info('Creating user ' + username + ' with htpasswd strategy');
      return self._htpasswdPlugin.adduser(username, password, callback);
    });
  } catch (err) {
    self._logger.error('Active Directory user existance check failed. Uncaught exception: ', err);
    err.status = err.status || 500;
    callback(err);
  }
};

module.exports = Plugin;