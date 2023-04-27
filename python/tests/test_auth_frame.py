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

import os
import pickle
import socket
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sdc.auth_frame import AuthFrame, CredentialsConf
from sdc.error import AuthMError
from tests.utils.mock_authmanager import start_auth_server


def foo():
    print("hello word")


def pick_unused_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock.getsockname()[1]


class TestAuthM(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestAuthM, self).__init__(*args, **kwargs)

        self.port = pick_unused_port()
        self.server = start_auth_server(self.port)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        self.pri_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.pub_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def test_get_pk(self):
        auth_frame = AuthFrame(
            f"127.0.0.1:{self.port}",
            "1083D6017E951017EB29611024D63D4DF73445DD880D1151E776541FEBE4A776",
            None,
            True,
        )
        self.assertGreater(len(auth_frame.get_public_key()), 0)

    def test_data_keys(self):
        auth_frame = AuthFrame(f"127.0.0.1:{self.port}", "test", None, True)
        foo_bytes = pickle.dumps(foo, protocol=4)
        data_uuid, _ = auth_frame.create_auth(
            b"",
            self.pub_key_pem.decode("utf-8"),
            self.pri_key_pem.decode("utf-8"),
            [foo_bytes],
            ["102787D0A74C12FFE0E0415C4588A49DDF1E7F02D6B0914A9F0D000690B8749B"],
        )
        auth_frame.get_data_keys(foo_bytes, [data_uuid])

    def test_get_prod(self):
        auth_frame = AuthFrame(f"127.0.0.1:{self.port}", "test", None)
        self.assertRaises(AuthMError, auth_frame.get_public_key)


if __name__ == "__main__":
    unittest.main()
