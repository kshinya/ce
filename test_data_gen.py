# pip install autopep8 pandas
# python test_code_gen.py
import autopep8
import re
import pandas as pd
import ipaddress
import json
from itertools import chain
import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import DNSName, IPAddress
from cryptography.x509.oid import NameOID

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


def expand_dns(values):
    match = re.match(r"^(.*?)\[(.*?)\](.*?)$", values)
    if not match:
        return [DNSName(values)]
    prefix, start_end, suffix = match.groups()
    start, end = start_end.split('...')
    zero_padded = len(start) > 1
    domains = []
    for i in range(int(start), int(end) + 1):
        if zero_padded:
            domain = DNSName(f'{prefix}{i:02}{suffix}')
        else:
            domain = DNSName(f'{prefix}{i}{suffix}')
        domains.append(domain)
    return domains


def expand_ip(values):
    result = []
    for ip in values:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                result.append(IPAddress(ipaddress.IPv4Address(f'{ip}')))
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                result.append(IPAddress(ipaddress.IPv6Address(f'{ip}')))
        except ValueError as e:
            print(f"無効なIPアドレスです: {ip}")
    return result


def create_csr(private_key: str, names: [x509.NameAttribute], option: []) -> str:
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(names))
    san_extension = x509.SubjectAlternativeName(option)
    csr = csr_builder.add_extension(san_extension, critical=False).sign(
        private_key, hashes.SHA256()
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def main():
    print("テストCSR生成しています...")
    test_codes: [str] = []
    file_path = 'test_gen2.tsv'
    data = pd.read_csv(file_path, sep='\t', keep_default_na=False)
    data_dict = data.to_dict(orient='records')
    command = []
    for record in data_dict:
        san = []
        dns = record.get('dns').split(',')
        parsed_dns = map(lambda dns_entry: expand_dns(dns_entry), dns)
        san += list(chain.from_iterable(parsed_dns))

        ip = record.get('ip').split(',')
        san += list(expand_ip(ip))
        names = []

        if (cn := record.get('cn')): names += [x509.NameAttribute(NameOID.COMMON_NAME, cn)]

        if (c := record.get('c')): names += [x509.NameAttribute(NameOID.COUNTRY_NAME, c)]

        if (s := record.get('s')): names += [x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s)]

        if (l := record.get('l')): names += [x509.NameAttribute(NameOID.LOCALITY_NAME, l)]

        if (o := record.get('o')): names += [x509.NameAttribute(NameOID.ORGANIZATION_NAME, o)]

        private_key = serialization.load_pem_private_key(
            key.encode('utf-8'),
            password=None # パスフレーズがある場合はここに渡す
        )
        csr = create_csr(private_key, names, san)

        name = f"test_{record.get('name')}"

        command.append(f"./win-acme.exe --source csr --csrfile {name}.csr --pkfile test_private_key.pem")


        print(f'------CSR {name}------')
        print("names")
        print(json.dumps(list(map(lambda value:str(value) ,names)), indent=4, ensure_ascii=False))
        print("san")
        print(json.dumps(list(map(lambda value: str(value), san)), indent=4, ensure_ascii=False))
        print(csr)
        print('\n\n\n')

        with open(f'test_datas/{name}.csr', 'w', encoding='utf-8') as file:
            # file.write(base_test_code + test_code)
            file.write(csr)

        with open(f'test_datas/{name}_data.txt', 'w', encoding='utf-8') as file:
            # file.write(base_test_code + test_code)
            params = list(map(lambda value: str(value), names)) + list(map(lambda value: str(value), san))
            file.write(json.dumps(params, indent=4, ensure_ascii=False))

    with open(f'test_datas/test_command.sh', 'w', encoding='utf-8') as file:
        file.write("\n".join(command))

    with open(f'test_datas/test_private_key.pem', 'w', encoding='utf-8') as file:
        file.write(key)

if __name__ == '__main__':
    main()
