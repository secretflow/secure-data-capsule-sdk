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

from cryptography.hazmat.primitives import hashes, hmac
from sdc.crypto import constants


def hmac_sha256(key: bytes, *args: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    assert (
        len(args) >= 1
    ), "At least one piece of data is involved in the calculation of hmac."
    h.update(args[0])
    for arg in args[1:]:
        h.update(constants.SEPARATOR)
        h.update(arg)
    return h.finalize()


def sha256(*args: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    assert (
        len(args) >= 1
    ), "At least one piece of data is involved in the calculation of hash."
    h.update(args[0])
    for arg in args[1:]:
        h.update(constants.SEPARATOR)
        h.update(arg)
    return h.finalize()


def gen_key() -> bytes:
    return secrets.token_bytes(constants.SYMM_KEY_SIZE_IN_BYTE)
