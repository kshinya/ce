from django.test import TestCase

from acme_srv.helper import logger_setup
from acme_srv.kos_ca_handler import CAhandler
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import re

class CaTest(TestCase):
    def setUp(self):

        self.debug = True
        self.logger = logger_setup(self.debug)
        with CAhandler(self.debug, self.logger) as ca_handler:
            self.ca_handler = ca_handler

        # 秘密鍵を生成
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # CSRの情報を定義
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),  # CN
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),  # O
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),  # OU
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),  # C
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),  # ST
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Minato-ku"),  # L
        ]))

        # CSRに署名
        csr = csr_builder.sign(
            private_key, hashes.SHA256()
        )
        # CSRをPEM形式で出力
        self.csr = re.sub(r"-----.*?-----\n", '', csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")) + "\n"


        # テスト用のデータを作成
        self.email = 'hogehoge@hoge.com'


    def test_dname(self):
        self.assertEqual(self.ca_handler._create_dname(self.csr),"cn=,o=My Organization,l=Tokyo,s=Minato-ku,c=JP")

    # def test_request_query(self):
    #     self.assertEqual(self.ca_handler._request_cert_query_data(self.csr, self.dname, self.email))

    # def test_enroll(self):
    #     self.assertEqual(self.ca_handler.enroll(self.csr, self.email), ('empty kos_gw_url', None, None, None))
