import base64
from unittest.mock import patch, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.test import TestCase
from acme_srv.helper import logger_setup
from acme_srv.kos_ca_handler import CAhandler
import sys

class KosCaHandlerTest(TestCase):

    def setUp(self):
        self.debug = False
        self.logger = logger_setup(self.debug)
        # import logging
        # logging.basicConfig(level=logging.CRITICAL)
        # self.logger = logging.getLog.test")

        with CAhandler(self.debug, self.logger) as ca_handler:
            self.ca_handler = ca_handler


    @patch('acme_srv.kos_ca_handler.requests.get')
    def exec(self,mock_get):
        args = sys.argv
        test_name = args[3]
        print(f"----------------------{test_name}----------------------")
        csr_path = args[4]
        req_id = 'AA***AA'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>{req_id}</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response
        email = "hogehoge@hoge.com"
        base64csr = None
        with open(csr_path, 'rb') as f:
            csr_data = f.read()
            csr = x509.load_pem_x509_csr(csr_data)
            der_csr = csr.public_bytes(serialization.Encoding.DER)
            base64csr = base64.b64encode(der_csr).decode('utf-8')

        dname = self.ca_handler._create_dname(base64csr)
        query_data = self.ca_handler._request_cert_query_data(base64csr, dname, email)
        self.ca_handler._request(query_data)

        mock_get.assert_called_once_with(
            'https://localhost',
            cert=('', '')
        )

