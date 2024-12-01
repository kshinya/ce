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

key = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCyxHJnsYKp/Zzv
0fyCXMGVpeec4WOWElrkMmesC7Qxv9gamYhIcom1+Wcw3a9adJlSVIO0nuw8/rqF
TUZp4tc1CO1fqErOA61nuvuGeyn61IIvZfQWeoLhap/L3luCKhTMYrmJ/J7fW3aR
qnIZtAL16+02873zB0Di23kK/6AxzGyLyjFT6PKlKuKPypYvYxEFUjPO2vcRlHhi
bfYKHRROK3ks5v2hbkLnSXcXksoiiMWa/zxlZkFpMPePjU7szGpe5gIdjlmLImPy
hQpTpWxKamQ5ApeYk5nMoh2yHSB4+iPh6MaL9PjhF8YwQRfsFP22rkq85Jb1K3zr
wRtzB0yTAgMBAAECggEAAW0YHTlTzwezGFCxtdfdQtSI1VNmUtIA//ViUVjjOPW3
A3ilFzA0EWEU0IAm6s78/Xn8y6nsPYz/WkU5t2o0CFFyv1gdh1ONLxjVR9yKAwfD
UB3SmtlNsP8DmQHu80oNp2xu3tRxRLE7RWyO2M37ALuUmrh1aU/DVev6pQ/8Aa8E
jszndHBseLsSlGrV27pwgbgzr2We/orxnHQooqKXlk4vDL6oebF32clogy9RPWmG
Qxr19BqcTw+y0M13wbSVLnSt14dU8KsxFXFb8Mb8sEdVhQ1/bNcAoeG9cymTfRuH
CEWkH+TLOVf77XTmyK81EGPMaZcIo3Ujo4UngSuSkQKBgQDnfsxSGVjtMf01ewpM
IJkG5XHFILPnLhrr8ga8zodYIUA974Ok+EjT6k6MwdIA5BOUCe/uxnNE9oPYrn91
L9+rGZOwFzaMu0iAc2j0Fu2aKnF7Da+JdOlGleYLHULm1+wjhTSDTgKDN8Qh0Z4m
IwoGulQzwDwgeyyX2RdqA9ONgwKBgQDFsMt6MePf/5oPldART1uCvixKpLMSF+WF
OevKbia5CwBGdHPOAJMXYY5QTDTy/uuE/Jb8eOOa7OtdeIpaba6JZDy2TJpTItyz
74KPcBWFnGlM3cohUJWcTvPkcJs7f2zChVdIHw7h97r8iKp/aZE/0BtZeCe9JvKG
aazdGSansQKBgE65WSSGSC6JtHFOgWb4IvIsbu85utRgYnlgmhf1KCO5Uw58+EjO
wn2GjeXiN9djuKC8bGLIDAUkzBuQ4/lnKWoXTZkxm7RqMDK2jLeNYInv6x2MvuhA
4N/HNC8NaWX1gfFmaEBK9CHJgiJ6FY0kl1FIZkAfHJNzL+wHwKWl3XifAoGAb8Hf
defoU8RSmsbthiufpwzNSzFKjkr2FNfGpXyZ5XgDotDIese2X7xl0J0UPd7A1EBb
NsU8nmObNw8i37Yruj3xWHl7sM3/iLU40M/jStI+cRbc4vKEcYXsuNKz3vHNUTZC
PmJYboQ2r/autDLAyxthqrWTeYogBr6M270RLjECgYEA48wNhQrzjATKNId9AaT+
J5xo+e/yR+0hyUFiTVNTA8adW8b7OVIhJcWkjAzQrCzEL2Xns5q8ckLwhQX+MMyl
M8Mr5TFg7B+Y7OJkAono9k7g2BbK4MiuCHNrKvmihM4UenX6M/ZmkYAALZBAGLT3
vCObzoxLmG7kZNufn2+h0oo=
-----END PRIVATE KEY-----'''


class KosCaHandlerTest(TestCase):

    def setUp(self):
        self.debug = False
        print(key.encode('utf-8'))
        self.private_key = serialization.load_pem_private_key(
            key.encode('utf-8'),
            password=None  # パスフレーズがある場合はここに渡す
        )

        # self.private_key = rsa.generate_private_key(
        #     public_exponent=65537,
        #     key_size=2048,
        # )

        # self.logger = logger_setup(self.debug)
        import logging
        from acme_srv.kos_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("django.test")

        with CAhandler(self.debug, self.logger) as ca_handler:
            self.ca_handler = ca_handler

    def gen_pem_private_key(self):
        pem = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        ).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        print(pem.decode('utf-8'))
        return pem

    def create_csr(self, names: [x509.NameAttribute], option: []) -> str:
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(names))
        san_extension = x509.SubjectAlternativeName(option)
        csr = csr_builder.add_extension(san_extension, critical=False).sign(
            self.private_key, hashes.SHA256()
        )
        der_csr = csr.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(der_csr).decode('utf-8')

    @patch('acme_srv.kos_ca_handler.requests.get')
    def test_base(self, mock_get):
        req_id = 'AA***AA'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>{req_id}</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.email = 'hogehoge@hoge.com'
        dns_names = [DNSName(f"sub{i:02}.example.com") for i in range(5, 15)]

        csr = self.create_csr([
            x509.NameAttribute(NameOID.COMMON_NAME, 'www1.com'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'JP'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Tokyo'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'Chiyoda-ku'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Organization'),
        ], [
               DNSName('example.com'),
               #     # DNSName('www.example.com'),
               IPAddress(ipaddress.IPv4Address('192.168.1.1')),
               #     # IPAddress(ipaddress.IPv6Address('::1')),
           ] + [DNSName(f"sub{i}.example.com") for i in range(5, 15)])

        self.assertEqual(self.ca_handler.enroll(csr), (None, None, None, req_id))

        mock_get.assert_called_once_with(
            'https://localhost?param1=value1',
            cert=('', '')
        )

