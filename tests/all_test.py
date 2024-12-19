import base64
from unittest.mock import patch, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.test import TestCase
from acme_srv.helper import logger_setup
from acme_srv.kos_ca_handler import CAhandler
import logging


class KosCaHandlerTest(TestCase):

    # def setUp(self):
    # self.debug = False

    @patch('acme_srv.kos_ca_handler.requests.get')
    def exec(self, mock_get):

        # logging.basicConfig(
        #     filename='log_file_name.log',
        #     level=logging.INFO,
        #     format='[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
        #     datefmt='%H:%M:%S'
        # )

        # logging.basicConfig(filename='_____________myapp.log', level=logging.DEBUG, filemode='a', handlers={
        #     'test': {
        #         'level': 'DEBUG',
        #         'class': 'logging.FileHandler',
        #         'filename': 'test222.log',  # Choose a file name and path
        #     },
        # })
        #
        # self.logger = logging.getLogger("acme2certifier")

        fileHandler = logging.FileHandler("___test.log")
        logger = logger_setup(True)
        logger.addHandler(fileHandler)

        with CAhandler(True, logger) as ca_handler:
            self.ca_handler = ca_handler

        req_id = 'AA***AA'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>{req_id}</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response
        email = "hogehoge@hoge.com"
        base64csr = None

        csr_path = "test_datas/test__004.csr"
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

    @patch('acme_srv.kos_ca_handler.requests.get')
    def test__001(self, mock_get):

        file_handler = logging.FileHandler(f"test_logs/_001.log")
        logger = logger_setup(True)
        logger.addHandler(file_handler)

        with CAhandler(True, logger) as ca_handler:
            self.ca_handler = ca_handler

        logger.debug("\n\n-------テストを開始します @_001-------")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>AAAA</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.ca_id = "CA2"
        self.ca_handler.policy_id = "ACME"
        self.ca_handler.stage_id = "aeac"
        email = "hoge@hoge.com"
        base64csr = None
        with open('./test_csr/san_001.CSR', 'rb') as f:
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
        logger.debug("-------テストを終了します @_001-------\n\n")

    @patch('acme_srv.kos_ca_handler.requests.get')
    def test__002(self, mock_get):

        file_handler = logging.FileHandler(f"test_logs/_002.log")
        logger = logger_setup(True)
        logger.addHandler(file_handler)

        with CAhandler(True, logger) as ca_handler:
            self.ca_handler = ca_handler

        logger.debug("\n\n-------テストを開始します @_002-------")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>AAAA</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.ca_id = "CA2"
        self.ca_handler.policy_id = "ACME"
        self.ca_handler.stage_id = "aeac"
        email = "hoge@hoge.com"
        base64csr = None
        with open('./test_csr/san_002.CSR', 'rb') as f:
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
        logger.debug("-------テストを終了します @_002-------\n\n")

    @patch('acme_srv.kos_ca_handler.requests.get')
    def test__003(self, mock_get):

        file_handler = logging.FileHandler(f"test_logs/_003.log")
        logger = logger_setup(True)
        logger.addHandler(file_handler)

        with CAhandler(True, logger) as ca_handler:
            self.ca_handler = ca_handler

        logger.debug("\n\n-------テストを開始します @_003-------")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>AAAA</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.ca_id = "CA2"
        self.ca_handler.policy_id = "ACME"
        self.ca_handler.stage_id = "aeac"
        email = "hoge@hoge.com"
        base64csr = None
        with open('./test_csr/san_003.CSR', 'rb') as f:
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
        logger.debug("-------テストを終了します @_003-------\n\n")

    @patch('acme_srv.kos_ca_handler.requests.get')
    def test__004(self, mock_get):

        file_handler = logging.FileHandler(f"test_logs/_004.log")
        logger = logger_setup(True)
        logger.addHandler(file_handler)

        with CAhandler(True, logger) as ca_handler:
            self.ca_handler = ca_handler

        logger.debug("\n\n-------テストを開始します @_004-------")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>AAAA</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.ca_id = "CA2"
        self.ca_handler.policy_id = "ACME"
        self.ca_handler.stage_id = "aeac"
        email = "hoge@hoge.com"
        base64csr = None
        with open('./test_csr/san_004.CSR', 'rb') as f:
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
        logger.debug("-------テストを終了します @_004-------\n\n")
