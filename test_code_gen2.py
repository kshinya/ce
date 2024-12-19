# pip install autopep8 pandas
# python test_code_gen.py
import autopep8
import re
import pandas as pd
import ipaddress
import json
from itertools import chain

def template(name: str, csr_path:str, ca_id:str,policy_id:str,stage_id:str,email:str):
    return f'''
    @patch('acme_srv.kos_ca_handler.requests.get')
    def test_{name}(self,mock_get):
    
    
        file_handler = logging.FileHandler(f"test_logs/{name}.log")
        logger = logger_setup(True)
        logger.addHandler(file_handler)
        
        with CAhandler(True, logger) as ca_handler:
            self.ca_handler = ca_handler
        
        logger.debug("\\n\\n-------テストを開始します @{name}-------")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<kos-gateway><req-detail><reqID>AAAA</reqID></req-detail></kos-gateway>"
        mock_get.return_value = mock_response

        self.ca_handler.ca_id = "{ca_id}"
        self.ca_handler.policy_id = "{policy_id}"
        self.ca_handler.stage_id = "{stage_id}"
        email = "{email}"
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
    file_path = 'test_gen.tsv'
    data = pd.read_csv(file_path, sep='\t', keep_default_na=False)
    data_dict = data.to_dict(orient='records')
    for record in data_dict:
        no = record.get('no')
        name = f'{no.replace(".","_")}'
        function_name = f"test_{name}"
        print(f"テスト関数名 {function_name}")
        params = {
            'name':name,
            'csr_path':f'./test_csr/san{name}.CSR',
            'ca_id': record.get('caID',""),
            'policy_id': record.get('policyID',""),
            'stage_id': record.get('stageID',""),
            'email': record.get('account'),
        }

        test_codes.append(template(**params))

    test_code = "\n".join(test_codes)


    with open('tests/test.py', 'r', encoding='utf-8') as file:
        base_test_code = file.read()

    with open('tests/all_test.py', 'w', encoding='utf-8') as file:
        # file.write(base_test_code + test_code)
        file.write(autopep8.fix_code(f"{base_test_code + test_code}", options={'max_line_length': 150}))




if __name__ == '__main__':
    main()
