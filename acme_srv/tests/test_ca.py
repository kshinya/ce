from django.test import TestCase
from pyasn1.type.base import Asn1Type
from pyasn1.type.univ import ObjectIdentifier
from pyasn1_modules.rfc2459 import UTF8String

from acme_srv.helper import logger_setup
from acme_srv.kos_ca_handler import CAhandler

from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import DNSName, IPAddress
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress

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

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chiyoda-ku"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]))

        custom_oid = ObjectIdentifier("1.2.392.200081.10.1.1.5.1.2")
        # custom_extension = x509.UnrecognizedExtension(custom_oid, b"www.10.com,www.11.com,www.12.com")
        # csr_builder = csr_builder.add_extension(custom_extension, critical=False)

        san_extension = x509.SubjectAlternativeName([
            DNSName("example.com"),
            # DNSName("www.example.com"),
            IPAddress(ipaddress.IPv4Address("192.168.1.1")),
            # IPAddress(ipaddress.IPv6Address("::1")),
        ])


        csr = csr_builder.add_extension(san_extension, critical=False).sign(
            private_key, hashes.SHA256()
        )

        print(csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"))
        # CSRをPEM形式で出力
        self.csr = re.sub(r"-----.*?-----\n", '', csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"))


        print("CSR")
        print(self.csr)
        print("CSR")


        # テスト用のデータを作成
        self.email = 'hogehoge@hoge.com'


    def test_dname(self):
        self.assertEqual(self.ca_handler._create_dname(self.csr),"cn=,o=My Organization,l=Tokyo,s=Minato-ku,c=JP")

    # def test_request_query(self):
    #     self.assertEqual(self.ca_handler._request_cert_query_data(self.csr, self.dname, self.email))

    # def test_enroll(self):
    #     self.assertEqual(self.ca_handler.enroll(self.csr, self.email), ('empty kos_gw_url', None, None, None))
