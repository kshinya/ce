from django.test import TestCase

from acme_srv.helper import logger_setup
from acme_srv.kos_ca_handler import CAhandler


class CaTest(TestCase):
    def setUp(self):

        self.debug = True
        self.logger = logger_setup(self.debug)
        with CAhandler(self.debug, self.logger) as ca_handler:
            self.ca_handler = ca_handler

        # テスト用のデータを作成
        self.email = 'hogehoge@hoge.com'
        self.dname = ''
        self.domains = []
        self.csr = '''
                MIICtjCCAZ4CAQAwcTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRIwEAYD
                VQQHDAlNaW5hdG8ta3UxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEVMBMGA1UEAwwM
                YXBpLnRlc3QuY29tMRAwDgYDVQQLDAdXZW5Vbml0MIIBIjANBgkqhkiG9w0BAQEF
                AAOCAQ8AMIIBCgKCAQEA2e0qMvPP4Kkz5Bc80FzQOddPValH9cXJhsRMqfgQaIsj
                ippCBNckzvLzz9fybF0LZVmGg5DVD3TwGw+q4IzuicgENaWekH53vE2KsuSCeANk
                LGfFzxWQ7LUWUGZpb8fUSqJDXSNI9Mmvf6CQx7xBE9CUbLN5DqTNWJ3zNYT7Yxaz
                nl7SRKnSyTDMMLCi6bVQPKfI+kCiQrOw9UkQAtLIrD1SHEC14eUDjYUJyyNvQt9s
                OxSYOr4n6spO5au31K/i0g3swgJ/nMLBhUkh5CA1YxIjs7zOJ+BuZmRkY0KSdcDw
                hkn6waIIX40Swku4yWi0NiY/WTenXvZRuR76v8uO+wIDAQABoAAwDQYJKoZIhvcN
                AQEFBQADggEBAKefQME49aYfbPls2bcAxg6fpDwkoD7l/g4JmUA50ovLHPDgNldm
                z/G/pmd71N3uPxN5pNaPlu5w8FUctusy00zADDt6/W/q/kLf7TWNWgrRd8RRQAm5
                RtgAoJJpBpChT48X1rt6OqGQeg3bNOIhBuE+S14W0MPZuqsyUpD5EvmvsThswn4v
                Q87aNMexffX/PYhemuGlHJ2VO/HQ0bmeCawaJv+2tWCtt2mc6nsfJ6zg6r4OCx8w
                IztJniPr3UfkGpEk/bqnEicHzozdcPvCdZv+j22jp+xkPbIQROCVMh9fFF2KmMic
                9BEwI4t6X8vlLeEBtM7zemA9smzYS1ypKIw=
                '''


    def test_dname(self):


        self.assertEqual(self.ca_handler._prepare_dns_names(self.csr))

    def test_request_query(self):
        self.assertEqual(self.ca_handler._request_cert_query_data(self.csr, self.dname, self.email))

    def test_enroll(self):
        self.assertEqual(self.ca_handler.enroll(self.csr, self.email), ('empty kos_gw_url', None, None, None))
