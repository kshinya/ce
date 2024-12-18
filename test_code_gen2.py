# pip install autopep8 pandas
# python test_code_gen.py
import autopep8
import re
import pandas as pd
import ipaddress
import json
from itertools import chain

def template(name: str, csr_path:str):

    return f'''
    @patch('acme_srv.kos_ca_handler.requests.get')
    def test_{name}(self,mock_get):
    
    
        fileHandler = logging.FileHandler(f"{name}.log")
        logger = logger_setup(True)
        logger.addHandler(fileHandler)
        
        with CAhandler(True, logger) as ca_handler:
            self.ca_handler = ca_handler
        
        logger.debug("\\n\\n-------テストを開始します @{name}-------")
        req_id = 'AA***AA'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>AAAA</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response
        email = "hogehoge@hoge.com"
        base64csr = None
        with open('{csr_path}', 'rb') as f:
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
        logger.debug("-------テストを終了します @{name}-------\\n\\n")
'''


def main():
    print("テストコード生成しています...")
    test_codes: [str] = []
    files: [str] = ['san2_aaaa.CSR']

    for file in files:
        name = file.replace(".CSR","")
        function_name = f"test_{name}"
        print(f"テスト関数名 {function_name}")
        print('\n\n\n')
        test_codes.append(template(name,f'./test_csr/{file}'))

    test_code = "\n".join(test_codes)


    with open('tests/test.py', 'r', encoding='utf-8') as file:
        base_test_code = file.read()

    with open('tests/all_test.py', 'w', encoding='utf-8') as file:
        # file.write(base_test_code + test_code)
        file.write(autopep8.fix_code(f"{base_test_code + test_code}", options={'max_line_length': 150}))




if __name__ == '__main__':
    main()
