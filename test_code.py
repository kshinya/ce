
@patch('acme_srv.kos_ca_handler.requests.get')
def test__001(self, mock_get):
    req_id = 'R100001'
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = f"<kos-gateway><req-detail><reqID>{req_id}</reqID></req-detail></kos-gateway>"
    mock_get.return_value = mock_response

    self.ca_handler.email = 'hoge@hoge.com'

    csr = self.create_csr(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chiyoda-ku"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization")
        ],
        [
            DNSName('www1.hoge.com'),
            DNSName('www2.hoge.com'),
            DNSName('www1.hoge.com'),
            DNSName('www2.hoge.com'),
            DNSName('www3.hoge.com'),
            DNSName('www4.hoge.com'),
            DNSName('www5.hoge.com'),
            DNSName('www6.hoge.com'),
            DNSName('www7.hoge.com'),
            DNSName('www8.hoge.com'),
            DNSName('www9.hoge.com'),
            DNSName('www10.hoge.com'),
            DNSName('www11.hoge.com'),
            DNSName('www12.hoge.com'),
            DNSName('www13.hoge.com'),
            DNSName('www14.hoge.com'),
            DNSName('www15.hoge.com'),
            DNSName('www16.hoge.com'),
            DNSName('www17.hoge.com'),
            DNSName('www18.hoge.com'),
            DNSName('www19.hoge.com'),
            DNSName('www20.hoge.com'),
            IPAddress(ipaddress.IPv4Address("192.168.0.1"))
        ]
    )

    self.assertEqual(self.ca_handler.enroll(csr), (None, None, None, req_id))

    mock_get.assert_called_once_with(
        "None",
        cert=("", "")
    )


@patch('acme_srv.kos_ca_handler.requests.get')
def test__002(self, mock_get):
    req_id = 'R100001'
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = f"<kos-gateway><req-detail><reqID>{req_id}</reqID></req-detail></kos-gateway>"
    mock_get.return_value = mock_response

    self.ca_handler.email = 'hoge@hoge.com'

    csr = self.create_csr(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "sample.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chiyoda-ku"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization")
        ],
        [
            DNSName('www1.hoge.com'),
            DNSName('www2.hoge.com'),
            DNSName('www01.hoge.com'),
            DNSName('www02.hoge.com'),
            DNSName('www03.hoge.com'),
            DNSName('www04.hoge.com'),
            DNSName('www05.hoge.com'),
            DNSName('www06.hoge.com'),
            DNSName('www07.hoge.com'),
            DNSName('www08.hoge.com'),
            DNSName('www09.hoge.com'),
            DNSName('www10.hoge.com'),
            DNSName('www11.hoge.com'),
            DNSName('www12.hoge.com'),
            DNSName('www13.hoge.com'),
            DNSName('www14.hoge.com'),
            DNSName('www15.hoge.com'),
            DNSName('www16.hoge.com'),
            DNSName('www17.hoge.com'),
            DNSName('www18.hoge.com'),
            DNSName('www19.hoge.com'),
            DNSName('www20.hoge.com'),
            IPAddress(ipaddress.IPv4Address("192.168.0.1"))
        ]
    )

    self.assertEqual(self.ca_handler.enroll(csr), (None, None, None, req_id))

    mock_get.assert_called_once_with(
        "None",
        cert=("", "")
    )


@patch('acme_srv.kos_ca_handler.requests.get')
def test__003(self, mock_get):
    req_id = 'R100001'
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = f"<kos-gateway><req-detail><reqID>{req_id}</reqID></req-detail></kos-gateway>"
    mock_get.return_value = mock_response

    self.ca_handler.email = 'hoge@hoge.com'

    csr = self.create_csr(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "sample.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chiyoda-ku"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization")
        ],
        [
            DNSName('www1.hoge.com'),
            DNSName('www2.hoge.com'),
            DNSName('www3.hoge.com'),
            DNSName('www4.hoge.com'),
            DNSName('www5.hoge.com'),
            DNSName('www6.hoge.com'),
            DNSName('www7.hoge.com'),
            DNSName('www8.hoge.com'),
            DNSName('www9.hoge.com'),
            DNSName('www10.hoge.com'),
            DNSName('www11.hoge.com'),
            DNSName('www12.hoge.com'),
            DNSName('www13.hoge.com'),
            DNSName('www14.hoge.com'),
            DNSName('www15.hoge.com'),
            DNSName('www16.hoge.com'),
            DNSName('www17.hoge.com'),
            DNSName('www18.hoge.com'),
            DNSName('www19.hoge.com'),
            DNSName('www20.hoge.com'),
            IPAddress(ipaddress.IPv4Address("192.168.0.1"))
        ]
    )

    self.assertEqual(self.ca_handler.enroll(csr), (None, None, None, req_id))

    mock_get.assert_called_once_with(
        "None",
        cert=("", "")
    )


@patch('acme_srv.kos_ca_handler.requests.get')
def test__004(self, mock_get):
    req_id = 'R100001'
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = f"<kos-gateway><req-detail><reqID>{req_id}</reqID></req-detail></kos-gateway>"
    mock_get.return_value = mock_response

    self.ca_handler.email = 'hoge@hoge.com'

    csr = self.create_csr(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "sample.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokyo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chiyoda-ku"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization")
        ],
        [
            DNSName('www1.hoge.com'),
            DNSName('www2.hoge.com'),
            IPAddress(ipaddress.IPv4Address("192.168.0.1")),
            IPAddress(ipaddress.IPv6Address("2001:DB8::8:800:200C:417A"))
        ]
    )

    self.assertEqual(self.ca_handler.enroll(csr), (None, None, None, req_id))

    mock_get.assert_called_once_with(
        "None",
        cert=("", "")
    )
