#!/usr/bin/env python3

import os
import requests
import json
import logging
import urllib3

# Surpress the insecure certificate warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

vault_token = os.environ.get('VAULT_TOKEN')
vault_addr = os.environ.get('VAULT_ADDR')

if not (vault_token, vault_addr):
    raise ValueError('Please set your VAULT TOKEN and/or VAULT ADDR')


def get_certificates():
    response = requests.request(method='LIST', url='{}/v1/pki/certs'.format(vault_addr), verify=False, headers={'X-Vault-Token': vault_token})

    if response.status_code == 200:
        data = json.loads(response.content.decode('utf-8'))
        keys = data["data"]["keys"]
        return keys
    else:
        return None

def revoke_certificate(certificate):
    payload = {
        "serial_number": str(certificate)
    }
    response = requests.request(method='POST', url='{}/v1/pki/revoke'.format(vault_addr), verify=False, headers={'X-Vault-Token': vault_token}, data=json.dumps(payload))

    if response.status_code == 200:
        data = json.loads(response.content.decode('utf-8'))
        revocation_time = data["data"]["revocation_time"]
        print(revocation_time)
        return revocation_time
    else:
        return None

def validate_revoked(certificate):
    response = requests.get(url='{}/v1/pki/cert/{}'.format(vault_addr, certificate), verify=False)

    if response.status_code == 200:
        data = json.loads(response.content.decode('utf-8'))
        revocation_time = data["data"]["revocation_time"]
        if revocation_time != 0:
            print('Revoke successful on {}'.format(certificate))
        else:
            print('Revoke failed on {}'.format(certificate))

def main():

    logging.basicConfig(level=logging.INFO)
    logging.info("Reading certificates from Vault...")
    data = get_certificates()

    logging.info("Starting to revoke certificates...")

    for certificate in data:
        logging.info("Revoking certificate {}".format(certificate))
        revoke_certificate(certificate)
        validate_revoked(certificate)

if __name__ == "__main__":
    main()


