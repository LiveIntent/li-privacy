# LiveIntent Privacy CLI

CLI to interact with the LiveIntent Privacy API

## Install
### Pip

```sh
pip install li-privacy
```

## Usage
```
$ li-privacy
usage: li-privacy [-h] [--version] {init,delete,optout} ...

Interact with the LiveIntent Privacy API

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

actions:
  {init,delete,optout}
    init                sets account configuration and generates keys
    delete              submits a data delete request for a user.
    optout              submits an optout request for a user.

For API documentation, see https://link.liveintent.com/privacy-api
```

For help with command options, add --help

### `init` command
Sets up the initial configuration and saves the parameters to a file.
```
$ li-privacy init --help
usage: li-privacy init [-h] [--config CONFIG] [--domain_name DOMAIN_NAME] [--key_id KEY_ID] [--signing_key SIGNING_KEY]

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       path to configuration file (defaults to config.json)
  --domain_name DOMAIN_NAME
                        your domain name. Use 'dailyplanet.com' to generate example keys and config
  --key_id KEY_ID       the signing key identifier
  --signing_key SIGNING_KEY
                        path to RSA-256 private signing key file. Will generate a new key-pair if missing.
```

All flags are optional; you will be prompted to enter values if none have been specified.

```
$ li-privacy init
Creating new config: config.json

Your domain name: publisher.com
Key Identifier: (key1) <ENTER>
Private RSA signing key file: (publisher.com.key) <ENTER>
Generated new keys in publisher.com.key and publisher.com.key.pub
Configuration written to config.json

To provision your keys, please email the following files to privacy@liveintent.com:
	config.json
	publisher.com.key.pub

```

If you already have an RSA signing key, you may provide the path to the existing file, otherwise, a new key will be generated.
You must submit your RSA public key (NOT YOUR PRIVATE KEY) and the config.json to the specified email address to have your account
provisioned and activated.

### `optout` and `delete` commands
`optout` and `delete` commands make use of the configured values and keys specified via the `init` command. 
You may use an alternative configuration file by passing  the `--config` option.

To `optout` a single user by email address:
```
$ li-privacy optout user@domain.com
{"reference":"01DYQAE3BV146Z1MX03B4J0RSM", "read":3, "imported":3}
```

The response in this case indicates that 3 records were opted out. This is due to the md5, sha1, and sha256 values for the specified email address.

To submit requests to the staging environment, add the `--staging` flag.
To specify a callback URL where you would like to receive the completion notice, add the `--callback_url https://<callback url>`
