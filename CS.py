#!/usr/bin/python -W ignore::DeprecationWarning
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
# Copyright 2013, High Energy Physics, Imperial College
#
""" Cert Sorcerer - A tool for requesting certificates.
    Version 1.0.2
"""

import os
import sys
import time
import getopt
import shutil
import pycurl
import socket
import StringIO
from xml.dom import minidom
from subprocess import Popen, PIPE
from OpenSSL import crypto
from OpenSSL.crypto import X509Req, X509Extension, PKey

# We need sha on RHEL5, but it's depreciated on RHEL6
# The warning is hidden by the default command line
import sha

# Default Settings
## Domain name to append to non-qualified hostnames
CS_DEF_DOMAIN = "grid.hep.ph.ic.ac.uk"
## Default e-mail for hostcerts
CS_DEF_EMAIL = "lcg-site-admin@ic.ac.uk"
# Set these to match your existing certs
CS_DEF_RA_OU = "Imperial"
CS_DEF_RA_L = "Physics"
CS_DEF_CA_O = "eScience"
CS_DEF_CA_C = "UK"
CS_DEF_KEYBITS = 2048
# SHA1 of the PIN you check with the RA (for hostcerts)
CS_DEF_PINHASH = sha.new("mypin").hexdigest()
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
CS_DEF_VERSION = "CertWizard 0.6.1"
CS_DEF_HOSTCERT = "/etc/grid-security/hostcert.pem"
CS_DEF_HOSTKEY = "/etc/grid-security/hostkey.pem"
CS_DEF_CERTPERMS = 0644
CS_DEF_KEYPERMS = 0600
CS_DEF_CSRPERMS = 0600
CS_DEF_STOREPERMS = 0700

# We store the full CA Chain here!
# This will get written out to the store directory
CS_DEF_CACHAIN = """-----BEGIN CERTIFICATE-----
MIIDhjCCAm6gAwIBAgIBADANBgkqhkiG9w0BAQUFADBUMQswCQYDVQQGEwJVSzEV
MBMGA1UEChMMZVNjaWVuY2VSb290MRIwEAYDVQQLEwlBdXRob3JpdHkxGjAYBgNV
BAMTEVVLIGUtU2NpZW5jZSBSb290MB4XDTA3MTAzMDA5MDAwMFoXDTI3MTAzMDA5
MDAwMFowVDELMAkGA1UEBhMCVUsxFTATBgNVBAoTDGVTY2llbmNlUm9vdDESMBAG
A1UECxMJQXV0aG9yaXR5MRowGAYDVQQDExFVSyBlLVNjaWVuY2UgUm9vdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM3ORtmmUHotwDTfAH5/eIlo3+BK
oElDeaeN5Sg2lhPu0laPch7pHKSzlqyHmZGsk3fZb8hBmO0lD49+dKnA31zLU6ko
Bje1THqdrGZPcjTm0lhc/SjzsBtWm4oC/bpYBACliB9wa3eSuU4Rqq71n7+4J+WO
KvaDHvaTdRYE3pyie2Xe5QTI8CXedCMh18+EdFvwlV79dlmNRNY93ZWUu6POL6d+
LapQkUmasXLjyjNzcoPXgDyGauHOqmyqxuPx4tDTsC25nKr+7K5k3T+lplJ/jMkQ
l/QHgqnABBXQILzzrt0a8nQdM8ONA+bht+8sy4eN/0zMulNj8kAzrutkhJsCAwEA
AaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FF74G0imd2spPC4AUzMrY6J7fpPAMB8GA1UdIwQYMBaAFF74G0imd2spPC4AUzMr
Y6J7fpPAMA0GCSqGSIb3DQEBBQUAA4IBAQCT0a0kcE8oVYzjTGrd5ayvOI+vbdiY
MG7/2V2cILKIts7DNdIrEIonlV0Cw96pQShjRRIizSHG5eH1kLJcbK/DpgX6QuPR
WhWR5wDJ4vaz0qTmUpwEpsT9mmyehhHbio/EsYM7LesScJrO2piD2Bf6pFUMR1LC
scAqN7fTXJSg6Mj6tOhpWpPwM9WSwQn8sDTgL0KkrjVOVaeJwlyNyEfUpJuFIgTl
rEnkXqhWQ6ozArDonB4VHlew6eqIGaxWB/yWMNvY5K+b1j5fdcMelzA45bFucOf1
Ag+odBgsGZahpFgOqKvBuvSrk/8+ie8I2CVYwT486pPnb5JFgHgUfZo8
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgICAQAwDQYJKoZIhvcNAQEFBQAwVDELMAkGA1UEBhMCVUsx
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
AaOBnzCBnDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjA5BgNVHR8E
MjAwMC6gLKAqhihodHRwOi8vY3JsLmNhLm5ncy5hYy51ay9jcmwvcm9vdC1jcmwu
ZGVyMB0GA1UdDgQWBBQSpb+Rn3/ir2pcCfLi+lngNuHzVTAfBgNVHSMEGDAWgBRe
+BtIpndrKTwuAFMzK2Oie36TwDANBgkqhkiG9w0BAQUFAAOCAQEAFQlXpYR45+fy
uKIh/c+7nIxODO5iWmKskxDSQhqhMCU8/d5WVfXZ35XoTakhhsxu+Q3smIa6AhbA
meAhIWc2kDgDatEUlMA5G3TQgUoQgjw5RAWxX5/7biaj2nSU7B4Nn5llOp4g+p9P
5H+wGm2KFhvslaoKBKhSUkM/1teS+XsoDjqaPp/4RQ80ywUYhVWJz18vH1ltWLQW
93i3mnLDDb+aOyeoxqIPCQSy6Q8nIYoM8e3jYvdjjZNruT45g6IK6bx7eQmEMfO+
u7qJiCKWGMxY+72ZeOw/0DMw4y8kU0wrl7gQ1o1Jk94hHNpBam+hX0Btc1K7YwXB
CemmHAuKQw==
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
    real_cn = cn.replace(" ", "_") # Make paths without spaces
    self._path = path
    self._cn = real_cn
    hostpath = os.path.join(path, real_cn)
    self._hostpath = hostpath
    self._paths = { CS_Const.CERT_FILE: os.path.join(hostpath,
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

  def write(self, file_type, data, perms = CS_DEF_KEYPERMS):
    """ (Over)write a file to the store. """
    fd = os.open(self._paths[file_type],
                 os.O_WRONLY | os.O_TRUNC | os.O_CREAT,
                 perms)
    file_out = os.fdopen(fd, "w")
    file_out.write(data)
    file_out.close()
    self.update()

  def read(self, file_type):
    """ Read an existing file from the store. """
    fd = os.open(self._paths[file_type], os.O_RDONLY)
    file_in = os.fdopen(fd, "r")
    pem = file_in.read()
    file_in.close()
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
    for key, value in self._paths.iteritems():
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
                 dn_ou = CS_DEF_RA_OU,
                 dn_l = CS_DEF_RA_L,
                 dn_o = CS_DEF_CA_O,
                 dn_c = CS_DEF_CA_C,
                 email = CS_DEF_EMAIL,
                 keybits = CS_DEF_KEYBITS,
                 ):
    """ Create a CSR PEM string for the given parameters. """
    if not store.get_state() == CS_Const.Nothing:
      raise "Certificate in wrong state to create new CSR."
    # Generate a key
    key = PKey()
    key.generate_key(crypto.TYPE_RSA, keybits)
    # Generate a CSR
    csr = X509Req()
    csr.set_pubkey(key)
    dn = csr.get_subject()
    dn.CN = dn_cn
    dn.OU = dn_ou
    dn.L = dn_l
    dn.O = dn_o
    dn.C = dn_c
    # Create the relevant extension
    if hostcert:
      ext_details = "email:DNS: %s" % dn_cn
    else:
      ext_details = "email:%s" % email
    ext = X509Extension("subjectAltName", False, ext_details)
    csr.add_extensions([ext])
    csr.sign(key, "md5")
    # Convert the CSR & KEY to PEM files
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    # Write them out to the store
    store.write(CS_Const.KEY_FILE, key_pem, CS_DEF_KEYPERMS)
    store.write(CS_Const.CSR_FILE, csr_pem, CS_DEF_CSRPERMS)
    # Just to be 100% sure everything is compabile...
    # ... Ensure the key is in PKCS#1 format
    CS_CertTools.pkcs8_to_pkcs1(store.get_path(CS_Const.KEY_FILE))

  @staticmethod
  def get_pubkey(store):
    """ Get the store public key (from the CSR) in PEM format. """
    # pyOpenssl has no accessor for the public key, we'll shell openssl
    if not store.get_state() >= CS_Const.CSR:
      raise "Certificate in wrong state to get public key."
    ssl_cmd = ["openssl",
               "req",
               "-in",
               store.get_path(CS_Const.CSR_FILE),
               "-pubkey",
               "-noout" ]
    p = Popen(ssl_cmd, stdout = PIPE, stderr = PIPE)
    key, _ = p.communicate()
    # Remove the guards from the key to get a plain base64 string
    key = key.replace("\n", "")
    key = key.replace("-----BEGIN PUBLIC KEY-----", "")
    key = key.replace("-----END PUBLIC KEY-----", "")
    return key

  @staticmethod
  def get_clientserial(path = CS_DEF_CERT):
    """ Get the serial of a certificate by path. """
    if not os.path.exists(path):
      raise "Client key not found while getting serial."
    file_in = open(path, "r")
    pem = file_in.read()
    file_in.close()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
    return cert.get_serial_number()

  @staticmethod
  def get_privateexp(keyfile = CS_DEF_KEY):
    """ Get the private exponent of a key file by path.
        This may prompt the user if the key is encrypted. """
    # This is another one not supported by pyOpenssl
    ssl_cmd = ["openssl", "rsa", "-in", keyfile, "-text", "-noout" ]
    p = Popen(ssl_cmd, stdout = PIPE)
    key_info, _ = p.communicate()
    if (p.returncode != 0):
      raise "Failed to get private exponent from openssl... Bad passphrase?"
    # Get just the private exponent from the text
    key_split = key_info.split("privateExponent:\n")[1]
    key_split = key_split.split("\nprime1:")[0]
    # Tidy up the exponent into a large hexadecimal number
    key_split = key_split.replace(" ", "")
    key_split = key_split.replace(":", "")
    key_split = key_split.replace("\n", "")
    return int(key_split, 16)

  @staticmethod
  def get_rawpubkey(certfile):
    """ Get the public key of a certificate in raw hexadecimal format of
        modulus.exponent """
    # Gets the public key as a lowercase hexadecimal string
    # Not possible in pyOpenssl, so we'll be shelling openssl again
    ssl_cmd = ["openssl", "x509", "-in", certfile, "-modulus", "-noout" ]
    p = Popen(ssl_cmd, stdout = PIPE)
    cert_info, _ = p.communicate()
    modulus = cert_info.split("=")[1].strip().lower()
    # We also need the exponent
    ssl_cmd = ["openssl", "x509", "-in", certfile, "-text", "-noout" ]
    p = Popen(ssl_cmd, stdout = PIPE)
    cert_info, _ = p.communicate()
    exponent = cert_info.split("Exponent:")[1]
    exponent = exponent.split("(")[1]
    exponent = exponent.split(")")[0]
    exponent = exponent.replace("0x", "").lower()
    return "%s.%s" % (modulus, exponent)

  @staticmethod
  def do_pppk(nonce, keyid, keyfile = CS_DEF_KEY):
    """ Create a PPPK respone string using the given challenge and keyfile. """
    # Is this a custom authentication algorithm? Google doesn't seem to know...
    # Ah well, Let's do it anyway:
    key_split = keyid.split(".")
    if not len(key_split) == 2:
      raise "Unexpected keyid format from CA."
    return_nonce = "%s:%u" % (nonce, time.time())
    return_nonce = return_nonce.lower().encode("hex")
    modulus = int(key_split[0], 16)
    base = int(return_nonce, 16)
    exponent = CS_CertTools.get_privateexp(keyfile)
    resp = pow(base, exponent, modulus)
    return "%x" % resp

  @staticmethod
  def pkcs8_to_pkcs1(keyfile):
    """ Converts a private key from PKCS8 format into PKCS1 format.
        Most grid software requires PKCS1 on all platforms. """
    # This is once again a job for openssl
    # but first create a temp file
    tmpfile = "%s.pkcs8" % keyfile 
    shutil.copy(keyfile, tmpfile)
    ssl_cmd = ["openssl", "rsa", "-in", tmpfile, "-out", keyfile ]
    p = Popen(ssl_cmd, stdout = PIPE)
    p.communicate()
    os.unlink(tmpfile)

class CS_RemoteCA:
  """ Functions for interacting with a remote CA via a web-service. """

  @staticmethod
  def _do_req(uri,
              data = None,
              cafile = None,
              usercert = None,
              userkey = None,
              with_pppk = CS_Const.No_PPPK):
    """ Post a request to a web server with authentication. """
    curl = pycurl.Curl()
    # Set the URL
    url = CS_DEF_URL % uri
    curl.setopt(curl.URL, url)
    # Attach any post data
    if data:
      curl.setopt(curl.POSTFIELDS, data)
    # Set the write function to write to a buffer
    body = StringIO.StringIO()
    headers = StringIO.StringIO()
    curl.setopt(curl.WRITEFUNCTION, body.write)
    curl.setopt(curl.HEADERFUNCTION, headers.write)
    # Set-up CA verification
    if cafile:
      curl.setopt(curl.CAINFO, cafile)
    else:
      curl.setopt(curl.SSL_VERIFYPEER, False)
    # PPPK is used instead!
    ## Set-up user authentication
    #if usercert and userkey:
    #  curl.setopt(curl.SSLCERT, usercert)
    #  curl.setopt(curl.SSLKEY, userkey)
    # Set-up stage 1 PPPK auth if required
    if with_pppk >= CS_Const.Lite_PPPK:
      ext_hdr = [ "PPPK: this is pppk",
                  "LocalHost: %s" % socket.gethostname() ]
      if with_pppk == CS_Const.Full_PPPK:
        userserial = CS_CertTools.get_clientserial(usercert)
        ext_hdr.append("serial: %u" % userserial)
      curl.setopt(curl.HTTPHEADER, ext_hdr)
    # Actually run the request...
    curl.perform()
    code = curl.getinfo(pycurl.HTTP_CODE)
    if not (with_pppk and (code == 401)):
      # Normal requests finish here
      # Return the return code & string
      curl.close()
      return (code, body.getvalue())
    # We got a 401 and PPPK is enabled, which means we can do PPPK auth now
    print "Starting PPPK authentication..."
    real_headers = headers.getvalue().split("\n")
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
      raise "Missing parameter in PPPK headers from CA."
    # Now we can do the PPPK algorithm
    resp_code = CS_CertTools.do_pppk(nonce, keyid, userkey)
    # Add the new auth codes to the headers
    ext_hdr += [ "realm: %s" % realm,
                 "keyid: %s" % keyid,
                 "response: %s" % resp_code ]
    curl.setopt(curl.HTTPHEADER, ext_hdr)
    # Reset the buffers and re-send the request
    body = StringIO.StringIO()
    headers = StringIO.StringIO()
    curl.setopt(curl.WRITEFUNCTION, body.write)
    curl.setopt(curl.HEADERFUNCTION, headers.write)
    curl.perform()
    code = curl.getinfo(pycurl.HTTP_CODE)
    curl.close()
    # Either we got a success code now, or some other error...
    return (code, body.getvalue())

  @staticmethod
  def post_csr(csrpem,
               hostcert,
               cafile = None,
               usercert = CS_DEF_CERT,
               userkey = CS_DEF_KEY,
               pinhash = CS_DEF_PINHASH,
               email = CS_DEF_EMAIL,
               renewal_cert = None,
               renewal_key = None):
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
      renewal_info = "<PublicKey>%s</PublicKey>" % oldcert_pubkey
      use_pppk = CS_Const.Lite_PPPK
      key = renewal_key
    # Fill out the fields in the CSR XML structure
    csr_xml = csr_xml % (csrpem, pinhash, email, renewal_info, CS_DEF_VERSION)
    # If requesting a user cert, clear the certs
    if not hostcert and not renewal_cert:
      usercert = None
      userkey = None
      use_pppk = CS_Const.No_PPPK
    code, data = CS_RemoteCA._do_req(csr_uri, csr_xml, cafile, usercert,
                                     key, use_pppk)
    if not code == 200 and not code == 201:
      raise "CA returned error code %d (%s) while sending CSR." % (code, data)

  @staticmethod
  def get_certid(pubkey,
                 cafile):
    """ Get the serial of a cert on the CA by public key (in PEM format). """
    req_uri = "resources/resource/publickey/%s" % pubkey
    code, data = CS_RemoteCA._do_req(req_uri, None, cafile)
    if not code == 200:
      raise "CA returned error code %d (%s) while getting cert id." % \
              (code, data)
    # Process the XML tree to get the certificate ID out
    doc = minidom.parseString(data)
    certs = doc.getElementsByTagName("certificate")
    if len(certs) < 1:
      return 0 # No ID yet / Public key not found
    if len(certs) > 1:
      raise "CA returned multiple certificates for public key. " \
            "This is not yet supported."
    id_elem = certs[0].getElementsByTagName("id")
    if not len(id_elem) == 1:
      raise "CA returned a certificate with multiple ID tags?"
    serial = id_elem[0].firstChild.data
    return int(serial)
    

  @staticmethod
  def get_cert(certid,
               cafile):
    """ Get a cert from the CA in PEM format by serial. """
    req_uri = "certificate/%u" % certid
    code, data = CS_RemoteCA._do_req(req_uri, None, cafile)
    if not code == 200:
      raise "CA returned error code %d (%s) while fetching cert." % (code, data)
    # Walk XML for the only X509Certificate certificate
    doc = minidom.parseString(data)
    certs = doc.getElementsByTagName("X509Certificate")
    if not len(certs) == 1:
      raise "CA returned multiple certificates in request?"
    cert_pem = certs[0].firstChild.data
    # Convert the result from unicode to a plain ascii string
    return cert_pem.encode("ascii", "ignore")


class CS_UI:
  """ Functions for interacting with the user and driving the certification
      process.
  """

  @staticmethod
  def confirm_user(prompt, batch = False):
    """ Give the user a yes/no choice with prompt and exit on "No". """
    if batch:
      return # In batch mode, print no prompt, just continue...
    while True:
      res = raw_input(prompt + " [y/N]? ")
      if res == "n" or res == "N" or len(res) == 0:
        print "Cancelling..."
        sys.exit(0)
      if res == "y" or res == "Y":
        break

  @staticmethod
  def new_cert(store, cn, hostcert):
    """ Get a new cert from the CA. """
    if hostcert:
      userpin = CS_DEF_PINHASH
      useremail = CS_DEF_EMAIL
    else:
      userpin = raw_input("Please enter a PIN for this request "
                          "(min 10 chars): ")
      if len(userpin) < 10:
        print "Pin must be at least 10 chars. Exiting."
        sys.exit(0)
      userpin = sha.new(userpin).hexdigest()
      useremail = raw_input("Please enter your (ideally .ac.uk) "
                            "e-mail address: ")
      CS_UI.confirm_user("Now ready to create & send request, continue")
    print "Generating keys..."
    CS_CertTools.create_csr(store, cn, hostcert)
    print "Sending CSR to CA..."
    csrpem = store.read(CS_Const.CSR_FILE)
    try:
      CS_RemoteCA.post_csr(csrpem,
                           hostcert,
                           store.get_path(CS_Const.CA_FILE),
                           pinhash = userpin,
                           email = useremail)
    except:
      print "An error occured. Removing CSR & Key..."
      store.clear() # Failure, reset request so it's easy to try again
      raise
    print "Done. You should receive an e-mail from the CA shortly."
    print ""
    if not hostcert:
      print "As this is a user cert, " \
            "you should add a key passphrase by running:"
      path = store.get_path(CS_Const.KEY_FILE)
      print "openssl rsa -in %s -out %s.tmp -des3" % (path, path)
      print "cp %s.tmp %s" % (path, path)
      print "rm %s.tmp" % path
      print ""

  @staticmethod
  def fetch_cert(store, hostcert, syscert = False):
    """ Retreive a signed cert from the CA. """
    pubkey = CS_CertTools.get_pubkey(store)
    print "Checking..."
    certid = CS_RemoteCA.get_certid(pubkey, store.get_path(CS_Const.CA_FILE))
    if certid <= 0:
      print "No information about this request from the CA is available yet."
      return
    print "Cert ID is: %d. Fetching..." % certid
    certpem = CS_RemoteCA.get_cert(certid, store.get_path(CS_Const.CA_FILE))
    store.write(CS_Const.CERT_FILE, certpem, CS_DEF_CERTPERMS)
    print "Completed."
    cert = store.get_path(CS_Const.CERT_FILE)
    key = store.get_path(CS_Const.KEY_FILE)
    print "Cert is at: %s" % cert
    print "Key is at: %s" % key
    print ""
    if not hostcert:
      print "As this is a user cert, you may want to install " \
            "these in your home dir by running:"
      print "mkdir -p ~/.globus"
      print "cp %s ~/.globus/usercert.pem" % cert
      print "cp %s ~/.globus/userkey.pem" % key
      print ""
      print "You may also want to create a .p12 file to import into " \
            "your browser by running:"
      print "openssl pkcs12 -export -in %s -inkey %s -out gridcert.p12" \
              % (cert, key)
      print "chown 600 gridcert.p12"
      print ""
    if syscert:
      print ""
      print "You may want to install the hostcert now " \
            "with the following commands:"
      print "cp %s /etc/grid-security/hostcert.pem" % cert
      print "cp %s /etc/grid-security/hostkey.pem" % key
      print ""
      print "Remember that some grid services will also need copies " \
            " in other locations updating and/or different permissions."
      print ""

  @staticmethod
  def renew_cert(store, cn, hostcert):
    """ Renew a certificate with the CA. """
    if hostcert:
      userpin = CS_DEF_PINHASH
      useremail = CS_DEF_EMAIL
    else:
      userpin = raw_input("Please enter a PIN for this renewal "
                          "(min 10 chars): ")
      if len(userpin) < 10:
        print "Pin must be at least 10 chars. Exiting."
        sys.exit(0)
      userpin = sha.new(userpin).hexdigest()
      useremail = raw_input("Please enter your (ideally .ac.uk) "
                            "e-mail address: ")
      CS_UI.confirm_user("Now ready to create & send renewal, continue")
    # Start by moving the old cert out of the way
    store.prepare_renew()
    print "Generating renewal request..."
    CS_CertTools.create_csr(store, cn, hostcert)
    print "Sending renewal CSR to CA..."
    csrpem = store.read(CS_Const.CSR_FILE)
    try:
      CS_RemoteCA.post_csr(csrpem,
                           hostcert,
                           store.get_path(CS_Const.CA_FILE),
                           pinhash = userpin,
                           email = useremail,
                           renewal_cert = store.get_path(CS_Const.OCERT_FILE),
                           renewal_key = store.get_path(CS_Const.OKEY_FILE))
    except:
      print "An error occured. Undoing renewal operations..."
      store.undo_renew()
      raise
    print "Done. You should receive an e-mail when the renewed cert is ready."


def print_help():
  print "Cert Sorcerer, Version: 1.0.1"
  print "Usage: CS.py [--batch] <cn of user or server>"
  print "   Or: CS.py [--batch] --sys"
  print ""
  print "The --sys option means operate on this machine's hostcert directly."
  print "The --batch options makes y/n prompts assume yes. Use with caution."
  print ""
  sys.exit(0)


if __name__ == "__main__":
  syscert = False
  batch = False

  # Process command line args
  try:
    optlist, args = getopt.getopt(sys.argv[1:], '', [ 'sys', 'batch', 'help' ])
  except getopt.GetoptError, err:
    print str(err)
    print_help()

  for opt in optlist:
    if opt[0] == "--sys":
      syscert = True
    elif opt[0] == "--batch":
      batch = True
    elif opt[0] == "--help":
      print_help()

  if not syscert:
    # Turn the remaining args into a string
    if len(args) < 1:
      print_help()
    cn = " ".join(args)
  else:
    if len(args) > 0:
      print "Extra argument(s) found after --sys?"
      sys.exit(0)
    cn = socket.gethostname()

  # If there is no space, assume hostname... Real users must have a space
  hostcert = not " " in cn
  if hostcert and not ("." in cn):
    # No domain name in hostcert cn, add it..
    cn += "." + CS_DEF_DOMAIN
  cn = cn.lower()

  # Tell the user how we've interpreted their input
  if hostcert:
    print 'Processing HOST cert with "CN=%s"...' % cn
  else:
    print 'Processing USER cert with "CN=%s"...' % cn

  store = CS_StoredCert(CS_DEF_STORE, cn)
  if syscert:
    # Consider the primary host cert for the machine
    store.promote()

  # Decide what to do based on the current state:
  state = store.get_state()
  if state == CS_Const.Nothing:
    CS_UI.confirm_user("There is no local data about this DN, "
                       "request a new cert", batch)
    CS_UI.new_cert(store, cn, hostcert)
  elif state == CS_Const.CSR:
    CS_UI.confirm_user("This cert is pending with the CA, "
                       "check for updates now", batch)
    CS_UI.fetch_cert(store, hostcert, syscert)
  elif state == CS_Const.Complete:
    CS_UI.confirm_user("This certificate has been previously signed, "
                       "start a renewal", batch)
    CS_UI.renew_cert(store, cn, hostcert)
  else:
    raise "Unknown Certificate State!"
  sys.exit(0)

