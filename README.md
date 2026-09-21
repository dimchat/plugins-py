# DIM Algorithm Plugins (Python)

[![License](https://img.shields.io/github/license/dimchat/plugins-py)](https://github.com/dimchat/plugins-py/blob/main/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dimchat/plugins-py/pulls)
[![Platform](https://img.shields.io/badge/Platform-Python%203-brightgreen.svg)](https://github.com/dimchat/plugins-py/wiki)
[![Issues](https://img.shields.io/github/issues/dimchat/plugins-py)](https://github.com/dimchat/plugins-py/issues)
[![Repo Size](https://img.shields.io/github/repo-size/dimchat/plugins-py)](https://github.com/dimchat/plugins-py/archive/refs/heads/main.zip)
[![Tags](https://img.shields.io/github/tag/dimchat/plugins-py)](https://github.com/dimchat/plugins-py/tags)
[![Version](https://img.shields.io/pypi/v/dimplugins)](https://pypi.org/project/dimplugins)

[![Watchers](https://img.shields.io/github/watchers/dimchat/plugins-py)](https://github.com/dimchat/plugins-py/watchers)
[![Forks](https://img.shields.io/github/forks/dimchat/plugins-py)](https://github.com/dimchat/plugins-py/forks)
[![Stars](https://img.shields.io/github/stars/dimchat/plugins-py)](https://github.com/dimchat/plugins-py/stargazers)
[![Followers](https://img.shields.io/github/followers/dimchat)](https://github.com/orgs/dimchat/followers)

## Dependencies

* Latest Versions

| Name | Version | Description |
|------|---------|-------------|
| [Ming Ke Ming (名可名)](https://github.com/dimchat/mkm-py) | [![Version](https://img.shields.io/pypi/v/mkm)](https://pypi.org/project/mkm) | Decentralized User Identity Authentication |
| [Dao Ke Dao (道可道)](https://github.com/dimchat/dkd-py) | [![Version](https://img.shields.io/pypi/v/dkd)](https://pypi.org/project/dkd) | Universal Message Module |
| [DIMP (去中心化通讯协议)](https://github.com/dimchat/core-py) | [![Version](https://img.shields.io/pypi/v/dimp)](https://pypi.org/project/dimp) | Decentralized Instant Messaging Protocol |

## Plugins

1. Data Coding
   * Base-58
   * Base-64
   * Hex
   * UTF-8
   * JsON
   * PNF _(Portable Network File)_
   * TED _(Transportable Encoded Data)_
2. Digest Digest
   * SHA-256
   * Keccak-256
   * RipeMD-160
3. Cryptography
   * AES-256 _(AES/CBC/PKCS7Padding)_
   * RSA-1024 _(RSA/ECB/PKCS1Padding)_, _(SHA256withRSA)_
   * ECC _(Secp256k1)_

### Plugin Loader

```python
from typing import Optional

from dimp import Base64
from dimap import PluginLoader
from dimap import Base64Coder


class CommonPluginLoader(PluginLoader):

    # Override
    def register_base64_coder(self):
        # Base64 coding
        Base64.coder = _PatchBase64Coder()


# Base-64
class _PatchBase64Coder(Base64Coder):

    # Override
    def decode(self, string: str) -> Optional[bytes]:
        string = self.trim_base64_string(b64=string)
        return super().decode(string=string)

    @staticmethod
    def trim_base64_string(b64: str) -> str:
        if '\n' in b64:
            b64 = b64.replace('\n', '')
            b64 = b64.replace('\r', '')
            b64 = b64.replace('\t', '')
            b64 = b64.replace(' ', '')
        return b64.strip()
```

This library is primarily designed to implement various algorithms in a plug-in manner, allowing you to further develop additional algorithms tailored to your specific applications.

----

Copyright &copy; 2018-2026 Albert Moky
[![Followers](https://img.shields.io/github/followers/moky)](https://github.com/moky?tab=followers)
