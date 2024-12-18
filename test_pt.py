# pip install autopep8 pandas
# python test_code_gen.py
import autopep8
import re
import pandas as pd
import ipaddress
import json
from itertools import chain

def template(name: str, email: str, names: [str], san: [str], mock_response: [str],
             asserts: [str]):
    if asserts is None:
        asserts = []
    if mock_response is None:
        mock_response = []

    return f'''
    @patch('acme_srv.kos_ca_handler.requests.get')
    def test_{name}(self,mock_get):
        self.logger.debug("\\n\\n-------テストを開始します @{name}-------")
        mock_response = MagicMock()
        {"\n".join(mock_response)}
        
        self.ca_handler.email = '{email}'
        
        csr = self.create_csr(
        [
            {",\n".join(list(map(lambda line:f"        {line}",names)))}
        ], 
        [
            {",\n".join(list(map(lambda line:f"        {line}",san)))}
        ]
        )
        
        {"\n".join(asserts)}
        
        self.logger.debug("-------テストを終了します @{name}-------\\n\\n")
        
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


    pt = ('kos_gateway_url','caID','policyID','stageID','account','CN','O','L','ST','C','dName','IPAddress','その他の属性')


    with open('tests/test_kos_ca_handler.py', 'w', encoding='utf-8') as file:
        # file.write(base_test_code + test_code)
        file.write(autopep8.fix_code(f"{base_test_code + test_code}", options={'max_line_length': 150}))




if __name__ == '__main__':
    main()
