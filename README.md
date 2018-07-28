# verdaccio-activedirectory
Extended Active Directory authentication plugin for verdaccio.

Firstly checks user in AD, then uses htpasswd authentication if not found.


## Installation

```sh
$ npm install verdaccio-activedirectory
```

## Config

Add to your `config.yaml`:

```yaml
auth:
  activedirectory:
    url: "ldap://10.0.100.1"
    baseDN: 'dc=sample,dc=local'
    domainSuffix: 'sample.local'
    extendedUsersFile: '/path/to/local/passwords/file'
```