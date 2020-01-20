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
usage: li-privacy {init,delete,optout} ...

Interact with the LiveIntent Privacy API

actions:
  {init,delete,optout}
    init                sets up the initial configuration
    delete              submits a data delete request for a user.
    optout              submits an optout request for a user.

For API documentation, see https://link.liveintent.com/privacy-api
```

For help with command options, add --help

### init
Sets up the initial configuration and saves the parameters to a file.
```
$ li-privacy init --help
usage: li-privacy init [-h] [--config CONFIG] [--domain_name DOMAIN_NAME]
                       [--signing_key SIGNING_KEY] [--key_id KEY_ID]

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       path to configuration file (Defaults to config.json)
  --domain_name DOMAIN_NAME
                        your website domain name
  --signing_key SIGNING_KEY
                        path to RSA-256 private signing key file
  --key_id KEY_ID       the signing key identifier
```

NOTE: All of the flags are optional; you will be prompted to enter values if none have been specified.

```
$ li-privacy init
Creating new config: config.json
Your website domain name: () www.dailyplanet.com
Key Identifier: (key1)
Path to Private RSA signing key file: (rsa256.key)
Generated new keys in rsa256.key and rsa256.key.pub
Configuration written to config.json
```

If you already have an RSA signing key, you may provide the path to the existing file, otherwise, a new key will be generated.
You must submit your RSA public key (NOT YOUR PRIVATE KEY) and the Key Identifier to your LiveIntent account representative for provisioning.

### optout/delete
Submitting an optout or delete request will make use of the configured values from your `init` command. 

```
$ li-privacy optout user@domain.com
{"reference":"01DYQAE3BV146Z1MX03B4J0RSM", "read":3, "imported":3}
```

The response in this case indicates that 3 records were opted out. This is due to the md5, sha1, and sha256 values for the specified email address.

To submit requests to the staging environment, add the `--staging` flag.
To specify a callback URL where you would like to receive the completion notice, add the `--callback_url https://<callback url>`
