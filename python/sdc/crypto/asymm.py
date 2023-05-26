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

from abc import ABC, abstractmethod
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secretflowapis.v1.sdc import digital_envelope_pb2


class Encryptor(ABC):
    def __init__(self, public_key: str):
        """init Encryptor

        Args:
            public_key: X509 public key, pem format
        """
        self.public_key = public_key

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass


class Decryptor(ABC):
    def __init__(self, private_key: str):
        """init Decryptor

        Args:
            private_key: PKCS#8 private key, pem format
        """
        self.private_key = private_key

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        pass


class Signer(ABC):
    def __init__(self, private_key: str):
        """init signer

        Args:
            private_key: PKCS#8 private key, pem format
        """
        self.private_key = private_key

    @abstractmethod
    def update(self, data: bytes):
        pass

    @abstractmethod
    def sign(self) -> bytes:
        pass


class Verifier(ABC):
    def __init__(self, public_key: str):
        """init verifier

        Args:
            public_key: X509 public key, pem format
        """
        self.public_key = public_key

    @abstractmethod
    def update(self, data: bytes):
        pass

    @abstractmethod
    def verify(self, signature: bytes) -> None:
        pass


class RsaEncryptor(Encryptor):
    def __init__(self, public_key: Union[bytes, str, rsa.RSAPublicKey]):
        if isinstance(public_key, bytes):
            self.public_key = serialization.load_pem_public_key(public_key)
        elif isinstance(public_key, str):
            self.public_key = serialization.load_pem_public_key(
                public_key.encode("utf-8")
            )
        else:
            self.public_key = public_key

    def encrypt(self, data: bytes) -> bytes:
        return self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

    def seal_asymm_secret(
        self, data: bytes, symm_key: bytes, iv: bytes, aad: bytes
    ) -> digital_envelope_pb2.AsymmetricSecret:
        """Seals RSA secret.

        Args:
            data: Plaintext data to be sealed.
            public_key: Public key for encrypting data key.
            aes_key: AES key for encrypting data.
            iv: Initial vector.
            aad: Authenticate additional data.

        Returns:
            An RsaSecret of digital envelope.
        """
        encryptor = Cipher(
            algorithms.AES(symm_key),
            modes.GCM(iv),
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(data) + encryptor.finalize()
        aes_secret = digital_envelope_pb2.SymmetricSecret(
            encrypted_data=ciphertext,
            encrypted_data_cmac=encryptor.tag,
            additional_authentication_data=aad,
            initial_vector=iv,
        )
        rsa_secret = digital_envelope_pb2.AsymmetricSecret(
            asymmetric_encrypted_key=self.encrypt(symm_key), symmetric_secret=aes_secret
        )
        return rsa_secret


class RsaDecryptor(Decryptor):
    def __init__(self, private_key: Union[str, rsa.RSAPrivateKey]):
        if isinstance(private_key, str):
            self.secret_key = serialization.load_pem_private_key(
                private_key.encode("utf-8"), password=None
            )
        else:
            self.secret_key = private_key

    def decrypt(self, data: bytes) -> bytes:
        return self.secret_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

    def open_asymm_secret(
        self, asymm_secret: digital_envelope_pb2.AsymmetricSecret
    ) -> bytes:
        """_summary_

        Args:
            digital_envelope_pb2 (_type_): _description_

        Returns:
            bytes: _description_
        """
        aes_key = self.decrypt(asymm_secret.asymmetric_encrypted_key)

        symm_secret = asymm_secret.symmetric_secret
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(symm_secret.initial_vector, symm_secret.encrypted_data_cmac),
        ).decryptor()
        decryptor.authenticate_additional_data(
            symm_secret.additional_authentication_data
        )
        decrypted_data = (
            decryptor.update(symm_secret.encrypted_data) + decryptor.finalize()
        )
        return decrypted_data


class RsaVerifier(Verifier):
    def __init__(self, public_key: str):
        super().__init__(public_key)
        self.hasher = hashes.Hash(hashes.SHA256())

    def update(self, data: bytes):
        self.hasher.update(data)
        return self

    def verify(self, signature: bytes) -> None:
        public_key = serialization.load_pem_public_key(self.public_key.encode("utf-8"))
        digest = self.hasher.finalize()
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )


class RsaSigner(Signer):
    def __init__(self, private_key: str):
        super().__init__(private_key)
        self.hasher = hashes.Hash(hashes.SHA256())

    def update(self, data: bytes):
        self.hasher.update(data)
        return self

    def sign(self) -> bytes:
        secret_key = serialization.load_pem_private_key(
            self.private_key.encode("utf-8"), password=None
        )
        digest = self.hasher.finalize()
        return secret_key.sign(
            digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
