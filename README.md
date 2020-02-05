# Installing python and pip
The li-privacy tool requires python. To verify that you have this installed correctly, you should be able to run the following command from a Terminal/Command Prompt:

```
$ python3 --version
  Python 3.7.1

$ pip3 --version
  pip 19.3.1 from … (python 3.7)
```

> *NOTE:* The specific version of python or pip that you have installed should not matter.

> *ERROR:* If you get an error that python3 or pip3 do not exist, try using:
```
python --version  # instead of python3
pip --version     # instead of pip3
```

If you do not already have python setup, then go download and install the latest version of python/pip for your operating system from https://www.python.org/downloads/.

> *NOTE:* During the installation, if there is an option to add python to your path, please be sure to select that option.

# Installing the li-privacy tool
Run the following command to automatically download and install the li-privacy client:
```
$ pip3 install li-privacy
  ...
  Installation takes place
  ...
Successfully installed li-privacy
```

> *ERROR:* Depending upon your python installation and permissions, you may receive an error that files or directories cannot be written. If this happens you can re-run the command with sudo:
```
$ sudo pip3 install li-privacy
```

or you may have success installing the package in "user" mode:
```
$ pip3 install --user li-privacy
```

To verify that the tool has been properly installed, run:
```
$ li-privacy --version
  li-privacy v.1.2.2
```

> *ERROR:* If you receive an error that li-privacy does not exist, then your python/pip installation is not properly setup to place installed modules in your executable path.

# Configuring your account and generating keys
The init command will begin the set up of your account. The program will prompt you for your company's domain name (for example, liveintent.com), a key-identifier, and the path to your signing key.

> *TIP:* If you already have an RSA signing key, you may provide the path to it here, otherwise, press <ENTER> for the key-identifier and Private RSA signing key questions and a new key will be automatically generated for you.

To set up your account, run the `init` command:
```
$ li-privacy init
Creating new config: config.json

Your domain name: *publisher.com*
Key Identifier: (key1) *<ENTER>*
Private RSA signing key file: (publisher.com.key) *<ENTER>*

Generated new keys in publisher.com.key and publisher.com.key.pub
Configuration written to config.json

To provision your keys, please email the following files to privacy@liveintent.com:
    config.json
    publisher.com.key.pub
```

The initialization process generates the following files:
| Filename             |  Description                                                |
| -------------------- | ----------------------------------------------------------- |
| config.json          | Contains the settings for your account. Send to LiveIntent. |
| <domainname>.key.pub | Your public RSA Key. Send to LiveIntent.                    |
| <domainname>.key     | Your private RSA Key. DO NOT SEND outside your company.     |

Once you have completed this process, email the two files to privacy@liveintent.com. Once your account has been setup, you will be notified and ready to submit transactions.

> *WARNING:* Be careful to submit the correct files, as the public and private key filenames are very similar.

# Using the dailyplanet.com example account
While you wait for your own account to be provisioned, you can utilize the example credentials provided in the API guide to submit practice requests to the staging system. As a convenience, the li-privacy tool will generate these for you.

Re-run the init command and when prompted for the domain name, enter "dailyplanet.com".

```
$ li-privacy init
Using existing config: config.json

Your domain name: *dailyplanet.com*

Generating example key and configuration
Saved example keys in dailyplanet.com.key and dailyplanet.com.key.pub

Configuration written to dailyplanet.json
```

To make use these example keys, simply add `--config dailyplanet.config` when running your command.

The daily planet configuration and keys are now available via the "dailyplanet.json" file. Pass the `--config dailyplanet.json` flag to use this account,.

```
$ li-privacy optout user@domain.com --config dailyplanet.json
{"reference":"01DZ1W5VCT6F0M1V345F8G07GY", "read":3, "imported":3}
```

# Using the li-privacy tool to optout or delete users
The following commands will only work after LiveIntent has provisioned your public key. While you wait for your keys to be established, you may use the dailyplanet.com example account for practice.

## Opt out a single user
To opt out a single user, call the `optout` command and provide a hash or an email address.

Opt out by hash example:
```
$ li-privacy optout cd2bfcffe5fee4a1149d101994d0987f
{"reference":"01DZ1TWYBXQ37M0N8VPAKM1RFB", "read":1, "imported":1}
```

If the command is successful, it will show a reference number and the number of records that were processed.

> *NOTE:* If an email address is specified, the address will automatically be hashed as MD5, SHA1, and SHA256 before submitting (thus the result shows 3 records):

Opt out by email example:
```
$ li-privacy optout user@domain.com
{"reference":"01DZ1KBHPKBRJG1D1DT8HP0ZBQ", "read":3, "imported":3}
```

## Opting out a list of users
If you have multiple users to opt out, you can specify the path to a text file containing the list of users. Each line in the file will be processed as a separate request and a report will be generated. The file should contain one email address or one hash per line, with no other columns or data.

Opt out multiple users example:
```
$ li-privacy optout path/to/users.txt
Processing users from file path/to/users.txt
...
Report saved to path/to/users.txt.20200101120000.tsv
```

## Deleting users
`delete` commands use the same parameters as `optout` commands, but the command name is `delete`.

```
$ li-privacy optout cd2bfcffe5fee4a1149d101994d0987f
{"reference":"01DZ1TWYBXQ37M0N8VPAKM1RFB", "read":1, "imported":1}
```
