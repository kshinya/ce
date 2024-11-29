from django.test import TestCase
import base64
from acme_srv.helper import logger_setup
from acme_srv.kos_ca_handler import CAhandler
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class CaTest(TestCase):

    def setUp(self):

        self.debug = True
        self.logger = logger_setup(self.debug)
        with CAhandler(self.debug, self.logger) as ca_handler:
            self.ca_handler = ca_handler


    def create_csr(self, names: [x509.NameAttribute], option: []) -> str:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(names))
        san_extension = x509.SubjectAlternativeName(option)
        csr = csr_builder.add_extension(san_extension, critical=False).sign(
            private_key, hashes.SHA256()
        )
        der_csr = csr.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(der_csr).decode('utf-8')


    def test_001(self):
        email = 'hogehoge@hoge.com'
        csr = self.create_csr([
            x509.NameAttribute(NameOID.COMMON_NAME, "www1.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chiyoda-ku"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization"),
        ], [])

        self.assertEqual(self.ca_handler.enroll(csr), ('empty kos_gw_url', None, None, None))




