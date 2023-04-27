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

import base64
import json
import pickle
import secrets
import uuid
from dataclasses import dataclass
from typing import List, Tuple

import grpc
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sdc.crypto import asymm, symm
from sdc.error import AuthMError
from sdc.ual import ual
from sdc.ual.constants import NONCE_SIZE_IN_SIZE
from secretflowapis.v1.sdc import core_pb2
from secretflowapis.v1.sdc.authmanager import auth_manager_pb2, auth_manager_pb2_grpc
from secretflowapis.v1.sdc.dataagent import data_agent_pb2
from secretflowapis.v1.sdc.teeapps import tee_task_params_pb2

DEFAULT_PARTITION_ID = "default"


@dataclass
class CredentialsConf:
    root_ca: bytes
    private_key: bytes
    cert_chain: bytes


def to_upper_hex(data: bytes):
    return "".join("{:02X}".format(x) for x in data)


class AuthFrame(object):
    def __init__(
        self, authm_host: str, authm_mr_enclave: str, conf: CredentialsConf, sim=False
    ):
        """AuthM client

        Args:
            authm_host: AuthManager endpoint
            authm_mr_enclave: AuthManager mr_enclave
            sim (bool, optional): is in simulation mode. Defaults to False.
        """
        self.sim = sim
        if conf is None:
            channel = grpc.insecure_channel(authm_host)
        else:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=conf.root_ca,
                private_key=conf.private_key,
                certificate_chain=conf.cert_chain,
            )
            channel = grpc.secure_channel(authm_host, credentials)

        self.stub = auth_manager_pb2_grpc.AuthManagerStub(channel)
        self.authm_mr_enclave = authm_mr_enclave

    def get_public_key(self) -> str:
        """Get Authmanager public key"""
        request = data_agent_pb2.GetRaCertPemsRequest()
        request.secret_shard_num = 1
        nonce_bytes = secrets.token_bytes(NONCE_SIZE_IN_SIZE)
        nonce = to_upper_hex(nonce_bytes)
        request.nonces.append(nonce)
        response = self.stub.GetRaCertPems(request)
        if response.status.code != 0:
            raise AuthMError(response.status.code, response.status.message)
        assert (
            len(response.report_with_certs) == 1
        ), "The AuthManager should have only one public key."
        report_with_cert = response.report_with_certs[0]

        if not self.sim:
            policy = core_pb2.UnifiedAttestationPolicy()
            rule = policy.main_attributes.add()
            rule.str_tee_platform = "SGX_DCAP"
            rule.hex_ta_measurement = self.authm_mr_enclave
            rule.bool_debug_disabled = "1"

            user_data = symm.sha256(
                report_with_cert.cert_pem.encode("utf-8"), nonce.encode("utf-8")
            )
            rule.hex_user_data = to_upper_hex(user_data)
            ual.verify_report(report_with_cert.attestation_report, policy)

        return report_with_cert.cert_pem

    def register_public_key(self, owner_id, pub_key_pem):
        request = data_agent_pb2.RegisterInsPubKeyRequest()
        request.ins_id = owner_id
        request.public_key.scheme = "RSA"
        request.public_key.public_key = pub_key_pem
        response = self.stub.RegisterInsPubKey(request)
        if response.status.code != 0 and response.status.code != 6:
            raise AuthMError(response.status.code, response.status.message)

    def get_data_keys(
        self, serialized_func: bytes, data_uuid_list: List[str]
    ) -> List[bytes]:
        """Get data keys

        Args:
            serialized_func: serialized function
            data_uuid_list (List[str]): TEEUObject data uuid

        Returns:
            List[bytes]: The data keys in the list correspond one-to-one to the elements in the `data_uuid_list`
        """
        tee_task_params = tee_task_params_pb2.TeeTaskParams()
        # tee_task_params.func = BASE64(SHA256(SERIALIZE(func)))

        func_hash = base64.b64encode(symm.sha256(serialized_func))
        tee_task_params.code = func_hash

        for data_uuid in data_uuid_list:
            input = tee_task_params.inputs.add()
            input.data_uuid = data_uuid
            input.partition_id = DEFAULT_PARTITION_ID

        # Generate temp RSA key-pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        pub_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # call authmanager service
        request = auth_manager_pb2.GetComputeMetaRequest()

        request.tee_task_params.CopyFrom(tee_task_params)
        request.public_key.scheme = "RSA"
        request.public_key.public_key = pub_key_pem
        # Generate RA Report
        if not self.sim:
            hasher = hashes.Hash(hashes.SHA256())
            digest = symm.sha256(
                request.tee_task_params.SerializeToString(deterministic=True),
                pub_key_pem,
            )
            report = ual.create_report("Passport", to_upper_hex(digest))
            request.attestation_report.CopyFrom(report)

        response = self.stub.GetComputeMeta(request)
        if response.status.code != 0:
            raise AuthMError(response.status.code, response.status.message)

        compute_meta_bytes = asymm.RsaDecryptor(private_key).open_asymm_secret(
            response.encrypted_response
        )

        compute_meta = auth_manager_pb2.ComputeMeta()
        compute_meta.ParseFromString(compute_meta_bytes)

        data_keys = []
        for data_uuid in data_uuid_list:
            input_meta = compute_meta.input_metas[data_uuid]
            partation_data_keys = input_meta.data_uri_with_dks.part_data_uris[0]
            data_keys.append(partation_data_keys.seg_data_uris[0].data_key)

        return data_keys

    def create_auth(
        self,
        data: bytes,
        public_key_pem: str,
        private_key_pem: str,
        allow_funcs: List[bytes],
        allow_enclaves: List[str],
    ) -> Tuple[str, bytes]:
        """Create data authorization information

        Args:
            data: object that need to be encrypted
            public_key: public key
            private_key : private key
            allow_funcs: specify functions(serialized) that can access the data
            allow_enclaves:  specify enclaves that can access the data

        Returns:
            tuple(data_uuid,  data_key)
        """

        # Data Mata

        data_meta = core_pb2.DataMeta()

        data_uuid = uuid.uuid4().hex
        data_meta.data_uuid = data_uuid

        # owner_id = base64(sha256(der(public key)))
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        pub_key_der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        owner_id = base64.b64encode(symm.sha256(pub_key_der))

        self.register_public_key(owner_id, public_key_pem)

        data_meta.owner_id = owner_id
        # The data sent into TEEU will not be in secret-sharing state,
        # so the `data_type` is `NONE`, and the `secret_shard_num` is 1
        data_meta.data_type = "NONE"
        data_meta.secret_shard_num = 1
        data_meta.source_type = "USER"

        # In the overall design of TEE data storage, in order to support data update
        # according to time increments, TEE data will be uploaded according to different partitions.
        # At present, the data received by `TEEU` is encrypted according to the whole,
        # so the partition field is a reserved field, which is uniformly set to `default`.
        data_meta.partition_num = 1
        partition_data_meta = data_meta.partition_data.add()
        partition_data_meta.partition_id = DEFAULT_PARTITION_ID
        # Considering that the data of a partition may be very large, it is
        # allowed to split the data into multiple segments during encryption.
        # However, currently the entire plaintext object is encrypted, so the
        # `segment_num`` is 1.
        partition_data_meta.segment_num = 1

        segment_data_meta = partition_data_meta.segment_data.add()
        segment_data_meta.segment_id = 0
        segment_data_meta.secret_shard_id = 0

        # random data key
        data_key = symm.gen_key()
        # encrypt data key
        authm_pub_key_pem = self.get_public_key()
        segment_data_meta.encrypted_data_key = asymm.RsaEncryptor(
            authm_pub_key_pem
        ).encrypt(data_key)

        # HMAC(data key, data_uuid || partition_id || segment_id || secret_shard_id || raw data)
        segment_data_meta.mac = symm.hmac_sha256(
            data_key,
            bytes(data_meta.data_uuid, "utf-8"),
            bytes(partition_data_meta.partition_id, "utf-8"),
            segment_data_meta.segment_id.to_bytes(4, byteorder="little"),
            segment_data_meta.secret_shard_id.to_bytes(4, byteorder="little"),
        )

        # SIG(data_uuid || partition_id  || segment_id || secret_shard_id || data key)
        segment_data_meta.signature = (
            asymm.RsaSigner(private_key_pem)
            .update(bytes(data_meta.data_uuid, "utf-8"))
            .update(bytes(partition_data_meta.partition_id, "utf-8"))
            .update(segment_data_meta.segment_id.to_bytes(4, byteorder="little"))
            .update(segment_data_meta.secret_shard_id.to_bytes(4, byteorder="little"))
            .update(data_key)
            .sign()
        )

        # Data Auth
        data_auth = core_pb2.DataAuth()
        data_auth.data_uuid = data_meta.data_uuid

        # In the TEE interface design, the authorization information needs to
        # specify which participants can use the data in the computing tasks initiated.
        # This field is reserved for TEEU, but in order to pass the authorization,
        # `all` needs to be added, so that the verification task initiation permission
        # is not required.
        data_auth.allowed_ins_ids.append("all")

        for allow_enclave in allow_enclaves:
            allowed_app = data_auth.allowed_apps.add()
            allowed_app.hex_mrenclave = allow_enclave

        # extra limite
        extra_limits_dict = {"limit_functions": []}
        for func in allow_funcs:
            func_hash = base64.b64encode(symm.sha256(func)).decode("utf-8")
            extra_limits_dict["limit_functions"].append(func_hash)
        data_auth.extra_limits = json.dumps(extra_limits_dict)

        # SIGN(data_uuid||allowed_ins_ids||allowed_apps||extra_limit)
        signer = asymm.RsaSigner(private_key_pem).update(
            data_auth.data_uuid.encode("utf-8")
        )
        for allowed_ins in data_auth.allowed_ins_ids:
            signer.update(allowed_ins.encode("utf-8"))
        for allowed_app in data_auth.allowed_apps:
            signer.update(allowed_app.SerializeToString(deterministic=True))
        signer.update(data_auth.extra_limits.encode("utf-8"))
        data_auth.signature = signer.sign()

        # call authmanager service
        request = data_agent_pb2.CreateDataWithAuthRequest()
        request.data_info.CopyFrom(data_meta)
        request.data_auth.CopyFrom(data_auth)
        response = self.stub.CreateDataWithAuth(request)
        if response.status.code != 0:
            raise AuthMError(response.status.code, response.status.message)
        return (data_uuid, data_key)
