# LiveIntent Privacy CLI

[![PyPi](https://img.shields.io/pypi/v/li-privacy)](https://pypi.org/project/li-privacy/)

CLI to interact with the LiveIntent Privacy API

## Install
### Pip

```sh
pip install li-privacy
```

Run as

```sh
li-privacy
```

### Docker

```sh
docker pull liveintent/li-privacy
```

Run as

```sh
docker run -it liveintent/li-privacy
```

## Usage

### init
Setup your initial configuration w/`li-privacy init`


```
li-privacy keygen
```

Enter your issuer website domain: www.liveintent.com
```

Generates RSA Key, sets Key ID, sets DN, saves to config file.

2.
```
li-privacy optout test@domain.com --config filename
```

