# -*- coding: utf-8 -*-
""" skeleton for customized CA handler """
from __future__ import print_function

from cryptography.x509 import IPAddress

# pylint: disable=e0401
from acme_srv.helper import load_config, csr_dn_get, error_dic_get, csr_cn_get, csr_load, csr_san_get, header_info_get
import requests
import xmltodict
from typing import List, Tuple
import json
import re

from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.err_msg_dic = error_dic_get(self.logger)
        self.parameter = None
        self.ca_id = None
        self.policy_id = None
        self.stage_id = None
        self.kos_gw_url = None
        self.client_cert = None
        self.client_key = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.parameter:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')

        if 'CAhandler' in config_dic and 'parameter' in config_dic['CAhandler']:
            self.parameter = config_dic['CAhandler']['parameter']

        if 'CAhandler' in config_dic and 'ca_id' in config_dic['CAhandler']:
            self.ca_id = config_dic['CAhandler']['ca_id']

        if 'CAhandler' in config_dic and 'policy_id' in config_dic['CAhandler']:
            self.policy_id = config_dic['CAhandler']['policy_id']

        if 'CAhandler' in config_dic and 'stage_id' in config_dic['CAhandler']:
            self.stage_id = config_dic['CAhandler']['stage_id']

        if 'CAhandler' in config_dic and 'kos_gw_url' in config_dic['CAhandler']:
            self.kos_gw_url = config_dic['CAhandler']['kos_gw_url']

        if 'CAhandler' in config_dic and 'client_cert' in config_dic['CAhandler']:
            self.client_cert = config_dic['CAhandler']['client_cert']

        if 'CAhandler' in config_dic and 'client_key' in config_dic['CAhandler']:
            self.client_key = config_dic['CAhandler']['client_key']

        self.logger.debug('CAhandler._config_load() ended')

    # KOSGatewayと通信する
    def _request(self, query_data: dict):
        error = None
        response_data = None
        try:
            query = '&'.join([f"{k}={v.encode('shift_jis').decode('latin1')}" for k, v in query_data.items()])
            full_url = f"{self.kos_gw_url}?{query}"
            if self.kos_gw_url:
                response = requests.get(full_url, cert=(self.client_cert, self.client_key))
                if response.status_code == 200:
                    self.logger.debug("success: %s", response.text)
                    response_data = xmltodict.parse(response.text)
                else:
                    self.logger.debug("error: %d", response.status_code)
                    error = self.err_msg_dic['serverinternal']
            else:
                return ("empty kos_gw_url", response_data)
        except requests.exceptions.RequestException as e:
            self.logger.debug("network error:", e)
            # 種別によってtimeout
            error = self.err_msg_dic['serverinternal']

        return (error, response_data)

    # KOSGatewayに証明書を申請するクエリパラメータを作成する
    def _request_cert_query_data(self, csr: str, dname: str, email: str):

        data = {
            'command': 'P10CertReq',
            'caID': self.ca_id,
            'policyID': self.policy_id,
            'appBlob': '',
            'dname': dname,
            'notBefore': '',
            'notAfter': '',
            'pkcss10': csr,
            'stageID': self.stage_id,
            'statusEmail': email,  # DB: account.contact
            'subID': '',
            'dataString': '',
            'cdataBytes': '',
            'validateOnly': '',
        }

        self.logger.debug('request_cert : %s', json.dumps(data, indent=4, ensure_ascii=False))
        return data

    def _check_cert(self, poll_identifier: str):
        result = False
        data = {
            'command': 'GetReqDetail',
            'reqID': poll_identifier,
        }

        (error, response_data) = self._request(data)
        if not error:
            result = response_data['kos-gateway']['req-detail']['certIssued'] == '1'

        return (error, result)

    def _download_cert(self, poll_identifier: str):
        cert_bundle = None
        cert_raw = None
        rejected = False
        (error, result) = self._check_cert(poll_identifier)
        if result:
            data = {
                'command': 'CertDownload',
                'reqID': poll_identifier,
                'includeChain': 'true'
            }
            (error, response_data) = self._request(data)
            if not error:
                cert_bundle = response_data['kos-gateway']['req-detail']['chain']  # PKCS7
                cert_raw = response_data['kos-gateway']['req-detail']['cert']

        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def _prepare_dns_names(self, dns_names: List[str], cn: str):
        limit = 51
        uniq_dns_names = list(dict.fromkeys(dns_names))
        if cn not in uniq_dns_names:
            if len(uniq_dns_names) < limit:
                uniq_dns_names.append(cn)
            else:
                uniq_dns_names[limit - 1] = cn
        return ','.join(uniq_dns_names[: limit])

    def _get_ipv4(self, ip_addresses: List[str]):
        return next((ip for ip in ip_addresses if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip)), "")

    def _create_dname(self, csr: str):

        cn = csr_cn_get(self.logger, csr)
        csr_object = csr_load(self.logger, csr)
        subject_dict = {attribute.oid._name: attribute.value for attribute in csr_object.subject}

        san = csr_san_get(self.logger, csr)
        dns_names =  [item[4:] for item in san if item.startswith('DNS:')]
        ip_addresses =  [item[3:] for item in san if item.startswith('IP:')]

        self.logger.debug('dns_names : %s', dns_names)
        self.logger.debug('ip_addresses : %s', ip_addresses)
        self.logger.debug('subject_dict : %s', subject_dict)
        self.logger.debug('dns_names : %s', self._prepare_dns_names(dns_names, cn))

        dname_param = {
            'cn': cn,
            'o': subject_dict.get('organizationName'),
            'l': subject_dict.get('localityName'),
            's': subject_dict.get('stateOrProvinceName'),
            'c': subject_dict.get('countryName', 'JP'),
            'dNSName': self._prepare_dns_names(dns_names, cn),
            'IPAddress': self._get_ipv4(ip_addresses)
        }
        return ",".join(f"{key}={value}" for key, value in dname_param.items() if value)

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None
        poll_indentifier = None

        cn = csr_cn_get(self.logger, csr)

        certificates = header_info_get(self.logger, csr, ('id', 'name', 'order__id', 'order__account__contact'))

        self.logger.debug("cn: %s", cn)
        self.logger.debug("certificates: %s", certificates)

        email = None
        try:
            emails = json.loads(certificates[0]['order__account__contact'])
            if emails:
                email = emails[0].replace('mailto:', '')
        except json.JSONDecodeError as e:
            self.logger.error('invalid email address', e)

        if not cn:
            error = self.err_msg_dic['badcsr']
        else:
            dname = self._create_dname(csr)
            query_data = self._request_cert_query_data(csr, dname, email)
            (error, response_data) = self._request(query_data)
            if not error:
                poll_indentifier = response_data['kos-gateway']['req-detail']['reqID']
        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        (error, cert_bundle, cert_raw, poll_identifier, rejected) = self._download_cert(poll_identifier)

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert: str, _rev_reason: str, _rev_date: str) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, payload: str) -> Tuple[str, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = None
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
