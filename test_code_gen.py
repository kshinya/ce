# pip install autopep8 pandas

import autopep8
import re
import pandas as pd
import ipaddress
import json
from itertools import chain

from past.builtins.noniterators import flatmap


def template(name: str, email: str, names: [str], san: [str], mock_response: [str],
             asserts: [str]):
    if asserts is None:
        asserts = []
    if mock_response is None:
        mock_response = []
    return f'''
@patch('acme_srv.kos_ca_handler.requests.get')
    def test_{name}(self,mock_get):
        mock_response = MagicMock()
        {"\n".join(mock_response)}
        
        self.ca_handler.email = '{email}'
        
        csr = self.create_csr(
        [
            {",\n".join(names)}
        ], 
        [
            {",\n".join(san)}
        ]
        )
        
        {"\n".join(asserts)}
        
        
'''


def expand_dns(values):
    match = re.match(r"^(.*?)\[(.*?)\](.*?)$", values)
    if not match:
        return [f"DNSName('{values}')"]
    prefix, start_end, suffix = match.groups()
    start, end = start_end.split('...')
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
                result.append(f"IPAddress(ipaddress.IPv4Address('{ip}'))")
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                result.append(f"IPAddress(ipaddress.IPv6Address('{ip}'))")
        except ValueError as e:
            print(f"無効なIPアドレスです: {ip}")
    return result


def main():
    print("テストコード生成しています...")
    test_codes: [str] = []
    file_path = './test_gen.tsv'
    data = pd.read_csv(file_path, sep='\t', keep_default_na=False)
    data_dict = data.to_dict(orient='records')
    for record in data_dict:
        san = []
        dns = record.get('dns').split(',')
        parsed_dns = map(lambda dns_entry: expand_dns(dns_entry), dns)
        san += list(chain.from_iterable(parsed_dns))

        ip = record.get('ip').split(',')
        san += list(expand_ip(ip))

        names = []

        if (cn := record.get('cn')): names += [f"x509.NameAttribute(NameOID.COMMON_NAME, '{cn}')"]

        if (c := record.get('c')): names += [f"x509.NameAttribute(NameOID.COUNTRY_NAME, '{c}')"]

        if (s := record.get('s')): names += [f"x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, '{s}')"]

        if (l := record.get('l')): names += [f"x509.NameAttribute(NameOID.LOCALITY_NAME, '{l}')"]

        if (o := record.get('o')): names += [f"x509.NameAttribute(NameOID.ORGANIZATION_NAME, '{o}')"]

        status = record.get('status')
        server_response = record.get('server_response')
        request_query = record.get('request_query')
        check_value = record.get('check_value')
        mock_response = []

        asserts = [
            f"self.assertEqual(self.ca_handler.enroll(csr), ({check_value}))"
        ]

        if status:
            mock_response += [
                f"mock_response.status_code = {status}",
            ]

            if request_query:
                asserts += [
                    f"\t\tmock_get.assert_called_once_with('{request_query}', cert=('', ''))"
                ]

        if server_response:
            mock_response += [
                f"\t\tmock_response.text = '{server_response}'",
            ]

        if len(mock_response):
            mock_response += [
                f"\t\tmock_get.return_value = mock_response",
            ]

        params = {
            'name': record.get('name'),
            'email': record.get('email'),
            'names': names,
            'san': san,
            'asserts': asserts,
            'mock_response': mock_response,
        }
        print('------作成パラメータ------')
        print(f"テスト関数名 test_{params['name']}")
        print(json.dumps(record, indent=4, ensure_ascii=False))
        print('\n\n\n')

        test_codes.append(autopep8.fix_code(template(**params), options={'max_line_length': 150}))

    with open('test_code.py', 'w', encoding='utf-8') as file:
        file.write("\n".join(test_codes))


if __name__ == '__main__':
    main()
