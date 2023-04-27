# Copyright 2023 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import secrets
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sdc.crypto import asymm


class TestAsymmCrypto(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestAsymmCrypto, self).__init__(*args, **kwargs)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        self.pub_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def test_rsa_encrypt(self):
        data = b"hello world!"
        data_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        secret = asymm.RsaEncryptor(self.pub_key_pem).seal_asymm_secret(
            data, data_key, iv, b""
        )
        result = asymm.RsaDecryptor(self.private_key).open_asymm_secret(secret)
        self.assertEqual(data, result)


if __name__ == "__main__":
    unittest.main()
