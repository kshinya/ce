from http.client import responses

from django.test import TestCase
import base64

from cryptography.x509 import DNSName, IPAddress
from acme_srv.helper import logger_setup

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress
import unittest
from unittest.mock import patch, mock_open, Mock, MagicMock

class CaTest(TestCase):

    def setUp(self):

        self.debug = False
        # self.logger = logger_setup(self.debug)

        import logging
        from acme_srv.kos_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')

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


    @patch('acme_srv.kos_ca_handler.requests.get')
    def test_001(self,mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<kos-gateway><req-detail><reqID>A****</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.email = 'hogehoge@hoge.com'
        dns_names = [DNSName(f"sub{i}.example.com") for i in range(5, 15)]
        # print( [
        #     DNSName("example.com"),
        #     #     # DNSName("www.example.com"),
        #         IPAddress(ipaddress.IPv4Address("192.168.1.1")),
        #     #     # IPAddress(ipaddress.IPv6Address("::1")),
        # ] + [DNSName(f"sub{i}.example.com") for i in range(5, 15)])

        csr = self.create_csr([
            x509.NameAttribute(NameOID.COMMON_NAME, "www1.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chiyoda-ku"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization"),
        ], [
            DNSName("example.com"),
            #     # DNSName("www.example.com"),
                IPAddress(ipaddress.IPv4Address("192.168.1.1")),
            #     # IPAddress(ipaddress.IPv6Address("::1")),
        ] + [DNSName(f"sub{i}.example.com") for i in range(5, 15)])

        print(self.ca_handler.email)

        self.assertEqual(self.ca_handler.enroll(csr), ('empty kos_gw_url2', None, None, None))




