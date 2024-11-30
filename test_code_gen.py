# pip install autopep8 pandas

import autopep8
import re
import pandas as pd
import ipaddress
from itertools import chain


def template(name: str, req_id: str, email: str, names: [str], san: [str], status: int = 200, request_query: str = ""):
    return f'''
@patch('acme_srv.kos_ca_handler.requests.get')
    def test_{name}(self,mock_get):
        req_id = '{req_id}'
        mock_response = MagicMock()
        mock_response.status_code = {status}
        mock_response.text = f"<kos-gateway><req-detail><reqID>{{req_id}}</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.email = '{email}'
        
        csr = self.create_csr(
        [
            {",\n".join(names)}
        ], 
        [
            {",\n".join(san)}
        ]
        )

        self.assertEqual(self.ca_handler.enroll(csr), (None, None, None, req_id))

        mock_get.assert_called_once_with(
            "{request_query}",
            cert=("", "")
        )
'''


def expand_dns(values):
    match = re.match(r"^(.*?)\[(.*?)\](.*?)$", values)
    if not match:
        return [f"DNSName('{values}')"]
    prefix, start_end, suffix = match.groups()
    start, end = start_end.split("...")
    zero_padded = len(start) > 1
    domains = []
    for i in range(int(start), int(end) + 1):
        if zero_padded:
            domain = f"DNSName('{prefix}{i:02}{suffix}')"
        else:
            domain = f"DNSName('{prefix}{i}{suffix}')"
        domains.append(domain)
    return domains


def expand_ip(values):
    result = []
    for ip in values:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                result.append(f'IPAddress(ipaddress.IPv4Address("{ip}"))')
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                result.append(f'IPAddress(ipaddress.IPv6Address("{ip}"))')
        except ValueError as e:
            print(f"無効なIPアドレスです: {ip}")
    return result


def main():
    test_codes: [str] = []
    file_path = './test_gen.tsv'
    data = pd.read_csv(file_path, sep='\t', keep_default_na=False)
    data_dict = data.to_dict(orient='records')
    for record in data_dict:
        san = []
        dns = record.get("dns").split(",")
        parsed_dns = map(lambda dns_entry: expand_dns(dns_entry), dns)
        san += list(chain.from_iterable(parsed_dns))

        ip = record.get("ip").split(",")
        san += list(expand_ip(ip))

        names = []

        cn = record.get("cn")
        if cn: names += [f'x509.NameAttribute(NameOID.COMMON_NAME, "{cn}")']

        c = record.get("c")
        if c: names += [f'x509.NameAttribute(NameOID.COUNTRY_NAME, "{c}")']

        s = record.get("s")
        if s: names += [f'x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "{s}")']

        l = record.get("l")
        if l: names += [f'x509.NameAttribute(NameOID.LOCALITY_NAME, "{l}")']

        o = record.get("o")
        if o: names += [f'x509.NameAttribute(NameOID.ORGANIZATION_NAME, "{o}")']

        test_codes.append(autopep8.fix_code(template(
            name=record.get("name"),
            req_id="R100001",
            email=record.get("email"),
            names=names,
            san=san,
            status=record.get("status"),
            request_query=record.get("params"),
        ),options={"max_line_length": 150}))
    #
    with open("test_code.py", "w", encoding="utf-8") as file:
        file.write("\n".join(test_codes))

main()
