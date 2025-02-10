#!/usr/bin/env python3
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# CS.py - Cert Sorcerer
# Copyright 2013-2025, High Energy Physics, Imperial College
#
""" Cert Sorcerer - A tool for requesting certificates.
    Version 1.1.1
"""
import os
import sys
import time
import getopt
import shutil
import socket
import getpass
import binascii
from io import BytesIO
from hashlib import sha1
from xml.dom import minidom

import pycurl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

VERSION = "CertSorcerer 1.1.1"

# Default Settings
# Default domain name: Hosts not matching this will print a warning
# You should update all parameters below when changing this.
CS_DEF_DOMAIN = "grid.hep.ph.ic.ac.uk"
# Default e-mail for hostcerts
CS_DEF_EMAIL = "lcg-site-admin@ic.ac.uk"
# Set these to match your existing certs
CS_DEF_RA_OU = "Imperial"
CS_DEF_RA_L = "Physics"
CS_DEF_CA_O = "eScience"
CS_DEF_CA_C = "UK"
CS_DEF_KEYBITS = 2048
# SHA1 of the PIN you check with the RA (for hostcerts)
# We default this to the hash of "mypin"
CS_DEF_PINHASH = "7dd1d706734923606b1483189a112ce2b2f3c644"
# Cert Store: This is where the certificates are put... Keep them safe!
CS_DEF_STORE = os.path.expanduser("~/.cs")
# The keys to use when talking to the CA (to ask for a new hostcert)
# These will never be written by this script, only read
CS_DEF_CERT = os.path.expanduser("~/.globus/usercert.pem")
CS_DEF_KEY = os.path.expanduser("~/.globus/userkey.pem")

###############################################################################

# You hopefully won't need to change things here
CS_DEF_CERTNAME = "cert.pem"
CS_DEF_KEYNAME = "key.pem"
CS_DEF_CSRNAME = "csr.pem"
CS_DEF_OCERTNAME = "cert.pem.old"
CS_DEF_OKEYNAME = "key.pem.old"
CS_DEF_CANAME = "ca.pem"
CS_DEF_URL = "https://cwiz-live.ca.ngs.ac.uk:443/%s"
CS_DEF_VERSION = VERSION
CS_DEF_HOSTCERT = "/etc/grid-security/hostcert.pem"
CS_DEF_HOSTKEY = "/etc/grid-security/hostkey.pem"
CS_DEF_CERTPERMS = 0o644
CS_DEF_KEYPERMS = 0o600
CS_DEF_CSRPERMS = 0o600
CS_DEF_STOREPERMS = 0o700

# We store the full CA Chain here!
# This will get written out to the store directory
CS_DEF_CACHAIN = """-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgICASMwDQYJKoZIhvcNAQELBQAwVDELMAkGA1UEBhMCVUsx
FTATBgNVBAoTDGVTY2llbmNlUm9vdDESMBAGA1UECxMJQXV0aG9yaXR5MRowGAYD
VQQDExFVSyBlLVNjaWVuY2UgUm9vdDAeFw0xMTA2MTgxMzAwMDBaFw0yNzEwMzAw
OTAwMDBaMFMxCzAJBgNVBAYTAlVLMRMwEQYDVQQKEwplU2NpZW5jZUNBMRIwEAYD
VQQLEwlBdXRob3JpdHkxGzAZBgNVBAMTElVLIGUtU2NpZW5jZSBDQSAyQjCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkLgb2eIcly4LZfj0Rf5F7s+HE/
6Tvpf4jsKkm7qs33y3EEudCbcPwQKjS2MgytPv+8xpEPHqy/hqTseNlZ6oJgc+V8
xlJ+0iws882Ca8a9ZJ/iGQH9UzXU4q35ArN3cbwoWAAvMvzZ6hUV86fAAQ1AueQN
6h7/tnfYfaUMiB4PNxucmouMHDJGmYzl47FtlLeHUr2c4m/oWSG5pADIvGFpWFHj
NIw8/x4n97w5/ks0tc/8/5Q6xzUfCX/VfqciQCvKcui2J5MBhUlBDLenzwqvUytB
4XAwX/pRcKmnFEYwoc9OKGExNx9tn9RjQYJAC/KLb44Jqno9l0eRxu3uw4sCAwEA
AaOBnzCBnDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4E
FgQUEqW/kZ9/4q9qXAny4vpZ4Dbh81UwHwYDVR0jBBgwFoAUXvgbSKZ3ayk8LgBT
Mytjont+k8AwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL2NybC5jYS5uZ3MuYWMu
dWsvY3JsL3Jvb3QtY3JsLmRlcjANBgkqhkiG9w0BAQsFAAOCAQEArd5TFOo9SzGW
0+KrAdzzf60zh4Wy//vZz4tgt7NeDbNpz2TZROBAClSu7oLPiruzgnhNP/Vxeu0s
pI41wRQsh0DVxhM+9ZFOskH+OdmHzKagoejvHh6Jt8WNN0eBLzN8Bvsue7ImJPaY
cf/Qj1ZTBhaRHcMsLNnqak3un/P+uLPxqSuxVKMtC8es/jqosS4czJ3dgs1hgFy9
nPQiwuIyf3OJ9eifAOGXk9Nlpha9C54zhc+hAkSLnpx/FhPjwLgpwDRgDJud6otH
15x3qZqXNx7xbYfeHaM1R1HMEjfVdzKCTY4zsqNEGPEF/0nUQSFk6KQVz0/ugNmI
9qoDx3FeEg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDiDCCAnCgAwIBAgIDAQAAMA0GCSqGSIb3DQEBCwUAMFQxCzAJBgNVBAYTAlVL
MRUwEwYDVQQKEwxlU2NpZW5jZVJvb3QxEjAQBgNVBAsTCUF1dGhvcml0eTEaMBgG
A1UEAxMRVUsgZS1TY2llbmNlIFJvb3QwHhcNMDcxMDMwMDkwMDAwWhcNMjcxMDMw
MDkwMDAwWjBUMQswCQYDVQQGEwJVSzEVMBMGA1UEChMMZVNjaWVuY2VSb290MRIw
EAYDVQQLEwlBdXRob3JpdHkxGjAYBgNVBAMTEVVLIGUtU2NpZW5jZSBSb290MIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzc5G2aZQei3ANN8Afn94iWjf
4EqgSUN5p43lKDaWE+7SVo9yHukcpLOWrIeZkayTd9lvyEGY7SUPj350qcDfXMtT
qSgGN7VMep2sZk9yNObSWFz9KPOwG1abigL9ulgEAKWIH3Brd5K5ThGqrvWfv7gn
5Y4q9oMe9pN1FgTenKJ7Zd7lBMjwJd50IyHXz4R0W/CVXv12WY1E1j3dlZS7o84v
p34tqlCRSZqxcuPKM3Nyg9eAPIZq4c6qbKrG4/Hi0NOwLbmcqv7srmTdP6WmUn+M
yRCX9AeCqcAEFdAgvPOu3RrydB0zw40D5uG37yzLh43/TMy6U2PyQDOu62SEmwID
AQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4E
FgQUXvgbSKZ3ayk8LgBTMytjont+k8AwHwYDVR0jBBgwFoAUXvgbSKZ3ayk8LgBT
Mytjont+k8AwDQYJKoZIhvcNAQELBQADggEBAAYaJ/u66lGwzRoZM24QZ3FvHIVi
LHyizT5L+GhGIPXQPvoQ0EaiMOQ1xUzMy96DMKfA7ltGOTyBlUm5KbxE2uj5azB/
NujdFkGXP+dom3gX7khYV38OBMVu8a/O6aqXmaI8I5mQzl0TwQ3cCVWJO1kzx96e
I7TRHZpGtng5rw4fuwdoOgoC/jXo0UOGki3YHMIFg+K9/d9yamdAfYmvbk3tfapT
slZumdeFaZpRZqnxTI+jqhJkt3bsfLO27JQgCz5glxoDdjnBsFbcDgKVZcw8hps8
9HduUIgoQHKnvVyuJoZiDXEFUH3Sonnf8LcnwvYPeaOHoriz0S4Q1RKug40=
-----END CERTIFICATE-----
"""


class CS_Const:
    """ Constants used by the other CS classes. """
    Nothing, CSR, Complete = range(3)
    KEY_FILE, CSR_FILE, CERT_FILE, OCERT_FILE, OKEY_FILE, CA_FILE = range(6)
    No_PPPK, Lite_PPPK, Full_PPPK = range(3)


class CS_StoredCert:
    """ A class for storing various files related to a single CN. """

    def __init__(self, path, cn):
        """ Initialise the store, creating the required directory structure. """
        real_cn = cn.replace(" ", "_")  # Make paths without spaces
        real_cn = real_cn.replace("/", "_")  # Also convert "/" chars
        self._path = path
        self._cn = real_cn
        hostpath = os.path.join(path, real_cn)
        self._hostpath = hostpath
        self._paths = {CS_Const.CERT_FILE: os.path.join(hostpath,
                                                        CS_DEF_CERTNAME),
                       CS_Const.KEY_FILE: os.path.join(hostpath,
                                                       CS_DEF_KEYNAME),
                       CS_Const.CSR_FILE: os.path.join(hostpath,
                                                       CS_DEF_CSRNAME),
                       CS_Const.OCERT_FILE: os.path.join(hostpath,
                                                         CS_DEF_OCERTNAME),
                       CS_Const.OKEY_FILE: os.path.join(hostpath,
                                                        CS_DEF_OKEYNAME),
                       CS_Const.CA_FILE: os.path.join(path,
                                                      CS_DEF_CANAME),
                       }
        # Create the cert store if needed
        if not os.path.exists(path):
            os.makedirs(path, CS_DEF_STOREPERMS)
        if not os.path.exists(self._paths[CS_Const.CA_FILE]):
            self.write(CS_Const.CA_FILE, CS_DEF_CACHAIN)
        elif os.path.getsize(self._paths[CS_Const.CA_FILE]) != len(CS_DEF_CACHAIN):
            # CA size is different, it is probably an older copy... Update it
            self.write(CS_Const.CA_FILE, CS_DEF_CACHAIN)
        if not os.path.exists(hostpath):
            os.mkdir(hostpath, CS_DEF_STOREPERMS)
        # If the user has imported some new certs by hand,
        #  there may be some permissions problems to fix
        # We only expect imports of CERT and KEY
        # Any other problems the user should fix manually!
        if os.path.exists(self._paths[CS_Const.CERT_FILE]):
            if not os.access(self._paths[CS_Const.CERT_FILE], os.R_OK | os.W_OK):
                os.chmod(self._paths[CS_Const.CERT_FILE], CS_DEF_CERTPERMS)
        if os.path.exists(self._paths[CS_Const.KEY_FILE]):
            if not os.access(self._paths[CS_Const.KEY_FILE], os.R_OK | os.W_OK):
                os.chmod(self._paths[CS_Const.KEY_FILE], CS_DEF_KEYPERMS)
        # Work out the current state
        self.update()

    def promote(self):
        """ Promote this store by importing the system hostcert. """
        # Don't do anything if the hostkey is already there,
        # Assume we've already imported the system ones.
        if os.path.exists(self._paths[CS_Const.KEY_FILE]):
            return
        # Import the system certificates
        # But don't overwrite or we'll lose the new key!!!
        # Also patch the permissions to known-good ones on import
        if os.path.exists(CS_DEF_HOSTCERT):
            if not os.path.exists(self._paths[CS_Const.CERT_FILE]):
                shutil.copy(CS_DEF_HOSTCERT, self._paths[CS_Const.CERT_FILE])
                os.chmod(self._paths[CS_Const.CERT_FILE], CS_DEF_CERTPERMS)
        if os.path.exists(CS_DEF_HOSTKEY):
            if not os.path.exists(self._paths[CS_Const.KEY_FILE]):
                shutil.copy(CS_DEF_HOSTKEY, self._paths[CS_Const.KEY_FILE])
                os.chmod(self._paths[CS_Const.KEY_FILE], CS_DEF_KEYPERMS)
        self.update()

    def update(self):
        """ See what files are present in the store to infer the cert state. """
        # Updates the current state of the cert
        # Assume we have nothing
        self._state = CS_Const.Nothing
        if os.path.exists(self._paths[CS_Const.CSR_FILE]):
            self._state = CS_Const.CSR
        if os.path.exists(self._paths[CS_Const.CERT_FILE]):
            self._state = CS_Const.Complete

    def write(self, file_type, data, perms=CS_DEF_KEYPERMS):
        """ (Over)write a file to the store. """
        fd = os.open(self._paths[file_type],
                     os.O_WRONLY | os.O_TRUNC | os.O_CREAT,
                     perms)
        with os.fdopen(fd, "w") as file_out:
            if isinstance(data,  str):
                file_out.write(data)
            else:
                try:
                    file_out.write(data.decode("ascii"))
                except:
                    print(f"Failed to write or decode object: {data}")
                    raise
        self.update()

    def read(self, file_type):
        """ Read an existing file from the store. """
        with open(self._paths[file_type], "r") as file_in:
            pem = file_in.read()
        return pem

    def prepare_renew(self):
        """ Remove the existing files to back-ups ready for a renew. """
        # Make back-ups of the old certs
        cur_path = self._paths[CS_Const.CERT_FILE]
        new_path = self._paths[CS_Const.OCERT_FILE]
        if os.path.exists(cur_path):
            shutil.copy(cur_path, new_path)
            os.unlink(cur_path)
        cur_path = self._paths[CS_Const.KEY_FILE]
        new_path = self._paths[CS_Const.OKEY_FILE]
        if os.path.exists(cur_path):
            shutil.copy(cur_path, new_path)
        # Delete the old CSR to go to new state
        cur_path = self._paths[CS_Const.CSR_FILE]
        if os.path.exists(cur_path):
            os.unlink(cur_path)
        self.update()

    def undo_renew(self):
        """ Restore the back-ups from the prepare_renew function. """
        # Copy the back-ups back into place
        cur_path = self._paths[CS_Const.CERT_FILE]
        new_path = self._paths[CS_Const.OCERT_FILE]
        if os.path.exists(new_path):
            shutil.copy(new_path, cur_path)
        cur_path = self._paths[CS_Const.KEY_FILE]
        new_path = self._paths[CS_Const.OKEY_FILE]
        if os.path.exists(new_path):
            shutil.copy(new_path, cur_path)
        self.update()

    def clear(self):
        """ Completely remove all the files for the given store. """
        for value in self._paths.values():
            if os.path.exists(value):
                os.unlink(value)
        self.update()

    def get_state(self):
        """ Get the current store state. """
        return self._state

    def get_path(self, file_type):
        """ Get the full path of a file in the store. """
        return self._paths[file_type]


class CS_CertTools:
    """ Functions for manipulating and querying X509 entities. """

    @staticmethod
    def create_csr(store,
                   dn_cn,
                   hostcert,
                   sans=None,
                   dn_ou=CS_DEF_RA_OU,
                   dn_l=CS_DEF_RA_L,
                   dn_o=CS_DEF_CA_O,
                   dn_c=CS_DEF_CA_C,
                   email=CS_DEF_EMAIL,
                   keybits=CS_DEF_KEYBITS,
                   ):
        """ Create a CSR PEM string for the given parameters. """
        if not store.get_state() == CS_Const.Nothing:
            raise RuntimeError("Certificate in wrong state to create new CSR.")
        # Generate a key
        key = rsa.generate_private_key(public_exponent=65537, key_size=keybits)
        # Generate CSR details
        x509name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, dn_c),
                              x509.NameAttribute(NameOID.LOCALITY_NAME, dn_l),
                              x509.NameAttribute(
                                  NameOID.ORGANIZATION_NAME, dn_o),
                              x509.NameAttribute(
                                  NameOID.ORGANIZATIONAL_UNIT_NAME, dn_ou),
                              x509.NameAttribute(NameOID.COMMON_NAME, dn_cn)])
        ext_details = []
        if hostcert:
            ext_details.append(x509.DNSName(dn_cn))
        else:
            ext_details.append(x509.RFC822Name(email))
        if sans:
            for san in sans:
                ext_details.append(x509.DNSName(san))
        ext = x509.SubjectAlternativeName(ext_details)
        # Build the full CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509name)
        builder = builder.add_extension(ext, critical=False)
        csr = builder.sign(key, hashes.SHA256())
        # Convert the CSR & KEY to PEM files
        key_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        # Write them out to the store
        store.write(CS_Const.KEY_FILE, key_pem, CS_DEF_KEYPERMS)
        store.write(CS_Const.CSR_FILE, csr_pem, CS_DEF_CSRPERMS)

    @staticmethod
    def get_pubkey(store):
        """ Get the store public key (from the CSR) in PEM format. """
        if not store.get_state() >= CS_Const.CSR:
            raise RuntimeError("Certificate in wrong state to get public key.")
        path = store.get_path(CS_Const.CSR_FILE)
        with open(path, "rb") as file_in:
            csr_pem = file_in.read()
        pubkey = x509.load_pem_x509_csr(csr_pem).public_key()
        key = pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        # Remove the guards from the key to get a plain base64 string
        key = key.replace("\n", "")
        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
        key = key.replace("-----END PUBLIC KEY-----", "")
        return key

    @staticmethod
    def get_clientserial(path=CS_DEF_CERT):
        """ Get the serial of a certificate by path. """
        if not os.path.exists(path):
            raise RuntimeError("Client key not found while getting serial.")
        with open(path, "rb") as file_in:
            pem = file_in.read()
        cert = x509.load_pem_x509_certificate(pem)
        return cert.serial_number

    @staticmethod
    def get_privateexp(keyfile=CS_DEF_KEY):
        """ Get the private exponent of a key file by path.
            This may prompt the user if the key is encrypted.
            Throws a ValueError if password is wrong.
        """
        with open(keyfile, "rb") as file_in:
            pem = file_in.read()
        # We have to handle encrypted keys here
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except TypeError:
            # Password required, get it as an ascii byte string
            passwd = getpass.getpass("Key password: ").encode('ascii')
            # This will raise an exception if the password is wrong which can
            # be caught by the caller (ValueError)
            key = serialization.load_pem_private_key(pem, password=passwd)
        return key.private_numbers().d

    @staticmethod
    def get_rawpubkey(certfile):
        """ Get the public key of a certificate in raw hexadecimal format of
            modulus.exponent """
        # Gets the public key as a lowercase hexadecimal string
        with open(certfile, "rb") as file_in:
            pem = file_in.read()
        cert = x509.load_pem_x509_certificate(pem)
        pubnum = cert.public_key().public_numbers()
        modulus = pubnum.n
        exponent = pubnum.e
        return f"{modulus:x}.{exponent:x}"

    @staticmethod
    def do_pppk(nonce, keyid, keyfile=CS_DEF_KEY):
        """ Create a PPPK respone string using the given challenge and keyfile. """
        # Is this a custom authentication algorithm? Google doesn't seem to know...
        # Ah well, Let's do it anyway:
        key_split = keyid.split(".")
        if not len(key_split) == 2:
            raise RuntimeError("Unexpected keyid format from CA.")
        return_nonce = f"{nonce}:{time.time():.0f}"
        return_nonce = binascii.hexlify(return_nonce.lower().encode("ascii"))
        modulus = int(key_split[0], 16)
        base = int(return_nonce, 16)
        exponent = CS_CertTools.get_privateexp(keyfile)
        resp = pow(base, exponent, modulus)
        return f"{resp:x}"


class CS_RemoteCA:
    """ Functions for interacting with a remote CA via a web-service. """

    @staticmethod
    def _do_req(uri,
                data=None,
                cafile=None,
                usercert=None,
                userkey=None,
                with_pppk=CS_Const.No_PPPK):
        """ Post a request to a web server with authentication. """
        curl = pycurl.Curl()
        # Set the URL
        url = CS_DEF_URL % uri
        curl.setopt(curl.URL, url)
        # Attach any post data
        if data:
            curl.setopt(curl.POSTFIELDS, data)
        # Set the write function to write to a buffer
        body = BytesIO()
        headers = BytesIO()
        curl.setopt(curl.WRITEFUNCTION, body.write)
        curl.setopt(curl.HEADERFUNCTION, headers.write)
        # Set-up CA verification
        if cafile:
            curl.setopt(curl.CAINFO, cafile)
        else:
            curl.setopt(curl.SSL_VERIFYPEER, False)
        # Set-up stage 1 PPPK auth if required
        if with_pppk >= CS_Const.Lite_PPPK:
            ext_hdrs = ["PPPK: this is pppk",
                        f"LocalHost: {socket.gethostname()}"]
            if with_pppk == CS_Const.Full_PPPK:
                userserial = CS_CertTools.get_clientserial(usercert)
                ext_hdrs.append(f"serial: {userserial}")
            curl.setopt(curl.HTTPHEADER, ext_hdrs)
        # Actually run the request...
        try:
            curl.perform()
        except pycurl.error as err:
            print(f'Pycurl error: "{str(err)}"')
            print('fcurl: "{curl.errstr()}"')
            print(
                'This is most likely the external server is having problems or is un-trusted.')
            raise
        code = curl.getinfo(pycurl.HTTP_CODE)
        if not (with_pppk and (code == 401)):
            # Normal requests finish here
            # Return the return code & string
            curl.close()
            return (code, body.getvalue().decode("ascii"))
        # We got a 401 and PPPK is enabled, which means we can do PPPK auth now
        print("Starting PPPK authentication...")
        real_headers = headers.getvalue().decode("ascii").split("\n")
        nonce = None
        keyid = None
        realm = None
        for header in real_headers:
            header = header.strip()
            if header.startswith("nonce: "):
                nonce = header.replace("nonce: ", "")
            if header.startswith("keyid: "):
                keyid = header.replace("keyid: ", "")
            if header.startswith("realm: "):
                realm = header.replace("realm: ", "")
        if not nonce or not keyid or not realm:
            raise RuntimeError("Missing parameter in PPPK headers from CA.")
        # Now we can do the PPPK algorithm
        resp_code = CS_CertTools.do_pppk(nonce, keyid, userkey)
        # Add the new auth codes to the headers
        ext_hdrs += [f"realm: {realm}",
                     f"keyid: {keyid}",
                     f"response: {resp_code}"]
        curl.setopt(curl.HTTPHEADER, ext_hdrs)
        # Reset the buffers and re-send the request
        body = BytesIO()
        curl.setopt(curl.WRITEFUNCTION, body.write)
        curl.perform()
        code = curl.getinfo(pycurl.HTTP_CODE)
        curl.close()
        # Either we got a success code now, or some other error...
        return (code, body.getvalue().decode("ascii"))

    @staticmethod
    def post_csr(csrpem,
                 hostcert,
                 cafile=None,
                 usercert=CS_DEF_CERT,
                 userkey=CS_DEF_KEY,
                 pinhash=CS_DEF_PINHASH,
                 email=CS_DEF_EMAIL,
                 renewal_cert=None,
                 renewal_key=None):
        """ Post a new certificate request with the given details to a CA. """
        key = userkey
        use_pppk = CS_Const.Full_PPPK
        renewal_info = ""
        csr_xml = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>""" \
                  """<CSR><Request>%s</Request><PIN>%s</PIN><Email>%s</Email>""" \
                  """%s<Version>%s</Version></CSR>"""
        csr_uri = "CSR"
        if hostcert and not renewal_cert:
            csr_xml = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>""" \
                      """<Bulk><CSR><Request>%s</Request><PIN>%s</PIN>""" \
                      """<Email>%s</Email>%s<Version>%s</Version></CSR></Bulk>"""
            csr_uri = "CSRs"
        # If we are doing a renewal, we have to include the original public key
        if renewal_cert:
            oldcert_pubkey = CS_CertTools.get_rawpubkey(renewal_cert)
            renewal_info = f"<PublicKey>{oldcert_pubkey}</PublicKey>"
            use_pppk = CS_Const.Lite_PPPK
            key = renewal_key
        # Fill out the fields in the CSR XML structure
        csr_xml = csr_xml % (csrpem, pinhash, email,
                             renewal_info, CS_DEF_VERSION)
        # If requesting a user cert, clear the certs
        if not hostcert and not renewal_cert:
            usercert = None
            userkey = None
            use_pppk = CS_Const.No_PPPK
        code, data = CS_RemoteCA._do_req(csr_uri, csr_xml, cafile, usercert,
                                         key, use_pppk)
        if not code == 200 and not code == 201:
            raise RuntimeError(
                f"CA returned error code {code} ({data}) while sending CSR.")

    @staticmethod
    def get_cert(pubkey,
                 cafile):
        """ Get the cert from the CA using the new POST interface.
            This is to avoid problems with double // in the URL.
        """
        req_uri = "resources/resource/publickey/pk"
        req_xml = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>""" \
                  f"""<PublicKey>{pubkey}</PublicKey>"""
        code, data = CS_RemoteCA._do_req(req_uri, req_xml, cafile)
        if not code == 200:
            raise RuntimeError(
                f"CA returned error code {code} ({data}) while fetching cert.")
        # Process the XML tree to get the certificate ID out
        doc = minidom.parseString(data)
        certs = doc.getElementsByTagName("X509Certificate")
        if len(certs) < 1:
            return None  # No cert yet / Public key not found
        if len(certs) > 1:
            raise RuntimeError("CA returned multiple certificates for public key. "
                               "This is not yet supported.")
        cert_pem = certs[0].firstChild.data
        # Convert the result from unicode to a plain ascii string
        return cert_pem.encode("ascii", "ignore")


class CS_UI:
    """ Functions for interacting with the user and driving the certification
        process.
    """

    @staticmethod
    def confirm_user(prompt, batch=False):
        """ Give the user a yes/no choice with prompt and exit on "No". """
        if batch:
            return  # In batch mode, print no prompt, just continue...
        while True:
            res = input(prompt + " [y/N]? ")
            if res in ('n', 'N') or len(res) == 0:
                print("Cancelling...")
                sys.exit(0)
            if res in ('y', 'Y'):
                break

    @staticmethod
    def new_cert(store, cn, hostcert, sans):
        """ Get a new cert from the CA. """
        if hostcert:
            userpin = CS_DEF_PINHASH
            useremail = CS_DEF_EMAIL
        else:
            userpin = input("Please enter a PIN for this request "
                            "(min 10 chars): ")
            if len(userpin) < 10:
                print("Pin must be at least 10 chars. Exiting.")
                sys.exit(0)
            sha = sha1()
            sha.update(userpin.encode("UTF-8"))
            userpin = sha.hexdigest()
            useremail = input("Please enter your (ideally .ac.uk) "
                              "e-mail address: ")
            CS_UI.confirm_user("Now ready to create & send request, continue")
        print("Generating keys...")
        CS_CertTools.create_csr(store, cn, hostcert, sans, email=useremail)
        print("Sending CSR to CA...")
        csrpem = store.read(CS_Const.CSR_FILE)
        try:
            CS_RemoteCA.post_csr(csrpem,
                                 hostcert,
                                 store.get_path(CS_Const.CA_FILE),
                                 pinhash=userpin,
                                 email=useremail)
        except:
            print("An error occured. Removing CSR & Key...")
            store.clear()  # Failure, reset request so it's easy to try again
            raise
        print("Done. You should receive an e-mail from the CA shortly.")
        print("")
        if not hostcert:
            print("As this is a user cert, "
                  "you should add a key passphrase by running:")
            path = store.get_path(CS_Const.KEY_FILE)
            print(f"openssl rsa -in {path} -out {path}.tmp -des3")
            print(f"cp {path}.tmp {path}")
            print(f"rm {path}.tmp")
            print("")

    @staticmethod
    def fetch_cert(store, hostcert, syscert=False):
        """ Retreive a signed cert from the CA. """
        pubkey = CS_CertTools.get_pubkey(store)
        print("Checking...")
        certpem = CS_RemoteCA.get_cert(
            pubkey, store.get_path(CS_Const.CA_FILE))
        if not certpem:
            print("No information about this request from the CA is available yet.")
            return
        certpem += b"\n"
        store.write(CS_Const.CERT_FILE, certpem, CS_DEF_CERTPERMS)
        print("Completed.")
        cert = store.get_path(CS_Const.CERT_FILE)
        key = store.get_path(CS_Const.KEY_FILE)
        print(f"Cert is at: {cert}")
        print(f"Key is at: {key}")
        print("")
        if not hostcert:
            print("As this is a user cert, you may want to install "
                  "these in your home dir by running:")
            print("mkdir -p ~/.globus")
            print(f"cp {cert} ~/.globus/usercert.pem")
            print("")
            print("For a user cert, you should add a password to the "
                  "private key at the same time:")
            print(f"openssl rsa -in {key} -out ~/.globus/userkey.pem -des3")
            print("")
            print("You may also want to create a .p12 file to import into "
                  "your browser by running:")
            print(
                f"openssl pkcs12 -export -in {cert} -inkey {key} -out gridcert.p12")
            print("chmod 600 gridcert.p12")
            print("")
        if syscert:
            print("")
            print("You may want to install the hostcert now "
                  "with the following commands:")
            print(f"cp {cert} /etc/grid-security/hostcert.pem")
            print(f"cp {key} /etc/grid-security/hostkey.pem")
            print("")
            print("Remember that some grid services will also need copies "
                  " in other locations updating and/or different permissions.")
            print("")

    @staticmethod
    def renew_cert(store, cn, hostcert):
        """ Renew a certificate with the CA. """
        if hostcert:
            userpin = CS_DEF_PINHASH
            useremail = CS_DEF_EMAIL
        else:
            userpin = input("Please enter a PIN for this renewal "
                            "(min 10 chars): ")
            if len(userpin) < 10:
                print("Pin must be at least 10 chars. Exiting.")
                sys.exit(0)
            sha = sha1()
            sha.update(userpin.encode("UTF-8"))
            userpin = sha.hexdigest()
            useremail = input("Please enter your (ideally .ac.uk) "
                              "e-mail address: ")
            CS_UI.confirm_user("Now ready to create & send renewal, continue")
        # Start by moving the old cert out of the way
        store.prepare_renew()
        print("Generating renewal request...")
        if hostcert:
            CS_CertTools.create_csr(store, cn, hostcert)
        else:
            # attach user e-mail as SAN for usercert
            CS_CertTools.create_csr(store, cn, hostcert, email=useremail)
        print("Sending renewal CSR to CA...")
        csrpem = store.read(CS_Const.CSR_FILE)
        try:
            CS_RemoteCA.post_csr(csrpem,
                                 hostcert,
                                 store.get_path(CS_Const.CA_FILE),
                                 pinhash=userpin,
                                 email=useremail,
                                 renewal_cert=store.get_path(
                                     CS_Const.OCERT_FILE),
                                 renewal_key=store.get_path(CS_Const.OKEY_FILE))
        except:
            print("An error occured. Undoing renewal operations...")
            store.undo_renew()
            raise
        print("Done. You should receive an e-mail when the renewed cert is ready.")


def print_help():
    """ Print the usage information for the program and exit. """
    print("Cert Sorcerer")
    print(
        "Usage: CS.py [--batch] [--fetch] [--san <san>] <cn of user or server>")
    print("   Or: CS.py [--batch] [--fetch] [--san <san>] --sys")
    print("")
    print("Option meanings:")
    print("  --sys -- Operate on this machine's hostcert directly.")
    print("  --fetch -- Don't prompt for fetching certificates from the CA.")
    print("  --batch -- Make y/n prompts assume yes. Use with caution.")
    print("  --san <san> -- Adds DNS SubjectAlternativeNames to new requests,")
    print("                 <san> should be just the domain name without any prefix,")
    print("                 Only valid for new requests (ignored otherwise).")
    print("")
    sys.exit(0)


def main():
    """ Main entry point. """
    syscert = False
    batch = False
    fetch = False
    sans = []

    # Process command line args
    try:
        optlist, args = getopt.getopt(sys.argv[1:], '',
                                      ['sys', 'batch', 'fetch', 'san=', 'help'])
    except getopt.GetoptError as err:
        print(str(err))
        print_help()

    for opt in optlist:
        if opt[0] == "--sys":
            syscert = True
        elif opt[0] == "--batch":
            batch = True
        elif opt[0] == "--fetch":
            fetch = True
        elif opt[0] == "--san":
            sans.append(opt[1])
        elif opt[0] == "--help":
            print_help()

    if not syscert:
        # Turn the remaining args into a string
        if len(args) < 1:
            print_help()
        cn = " ".join(args)
    else:
        if len(args) > 0:
            print("Extra argument(s) found after --sys?")
            sys.exit(0)
        cn = socket.gethostname()

    # If there is no space, assume hostname... Real users must have a space
    hostcert = " " not in cn
    cn = cn.lower()
    if hostcert and not cn.endswith(CS_DEF_DOMAIN):
        # Domain name doesn't end in our expected default
        # This might be a mistake if the script hasn't been customised
        print("Cert domain name doesn't match expected built-in value!")
        print(f"Updates about this cert will be sent to: {CS_DEF_EMAIL}")
        CS_UI.confirm_user("Are you sure that this is correct?")

    # Tell the user how we've interpreted their input
    dn = f"OU={CS_DEF_RA_OU},L={CS_DEF_RA_L},O={CS_DEF_CA_O},C={CS_DEF_CA_C}"
    if hostcert:
        print(f'Processing HOST cert with "CN={cn}" ({dn}).')
    else:
        print(f'Processing USER cert with "CN={cn}" ({dn}).')

    store = CS_StoredCert(CS_DEF_STORE, cn)
    if syscert:
        # Consider the primary host cert for the machine
        store.promote()

    # Decide what to do based on the current state:
    state = store.get_state()
    if state == CS_Const.Nothing:
        if fetch:
            print("No existing data about this request, "
                  "run again without --fetch to continue.")
            sys.exit(0)
        CS_UI.confirm_user("There is no local data about this DN, "
                           "request a new cert", batch)
        # Check that a usercert and key are accessible for the request if it's
        # for a hostcert...
        if hostcert and ((not os.access(CS_DEF_CERT, os.R_OK))
                         or (not os.access(CS_DEF_KEY, os.R_OK))):
            print("A valid usercert & key must be installed at the following "
                  "paths to request a new hostcert:")
            print(f"{CS_DEF_CERT}")
            print(f"{CS_DEF_KEY}")
            sys.exit(1)
        CS_UI.new_cert(store, cn, hostcert, sans)
    elif state == CS_Const.CSR:
        CS_UI.confirm_user("This cert is pending with the CA, "
                           "check for updates now", fetch or batch)
        CS_UI.fetch_cert(store, hostcert, syscert)
    elif state == CS_Const.Complete:
        if fetch:
            print("Certificate already signed, "
                  "run again without --fetch to continue.")
            sys.exit(0)
        if sans:
            print("ERROR: SANs can't be used with renewal.\n"
                  "To 'renew' SAN certificates, delete the local data and \n"
                  "start the request from scratch.")
            sys.exit(1)
        CS_UI.confirm_user("This certificate has been previously signed, "
                           "start a renewal", batch)
        CS_UI.renew_cert(store, cn, hostcert)
    else:
        raise RuntimeError("Unknown Certificate State!")
    sys.exit(0)


if __name__ == "__main__":
    main()
