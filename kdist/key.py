#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
import boto.sts
from .platform import invoke

class KeyManager(object):
    """
    Manage secrets betweeen AWS Key Management Service (KMS) and GnuPG and
    create temporary credentials useing AWS Secure Token Service (STS).

    Private keys are kept encrypted (via KMS) in memory for as long as
    possible.  Keys stored in S3 are always client-side encrypted via KMS.

    KeyManager objects have the following attributes:
    
    s3_region/kms_region/sts_region: The region to use when communicating
    with these services.

    bucket_name: The S3 bucket containing the GnuPG private key.
    
    key_name: The name of the key.  This is used to determine the name of
    the S3 object and the KMS key name.

    role_arn: The AWS ARN of the role to assume.

    role_session_name: The name of the session to use when assuming the role.

    role_external_id: The external id provided by the credential provider when
    calling AssumeRole.  This is used to prevent the confused deputy problem.

    encrypted_private_key: The GnuPG private key encrypted by KMS.  This must
    be populated by get_private_key_from_gpg() or
    download_private_key_from_s3().
    
    public_key: The GnuPG public key.  This must be populated by
    get_public_key_from_gpg() or download_public_key_from_s3().

    
    """
    s3_region = kms_region = sts_region = "us-west-2"
    bucket_name = "dist-admin"
    key_name = "dist-admin"
    role_arn = "arn:aws:iam::557925715019:role/dist-admin"
    role_external_id = None
    role_session_name = "dist-admin"
    
    def __init__(self, s3_region=None, kms_region=None, sts_region=None,
                 bucket_name=None, key_name=None, role_arn=None,
                 role_session_name=None, role_external_id=None):
        """
        KeyManager(s3_region=None, kms_region=None, sts_region=None,
                   bucket_name=None, key_name=Nole_arn=None,
                   role_session_name=None, role_external_id=None)

        Create a new KeyManager object.  Overrides for the defaults provided
        by the class can be specified here.
        """
        super(KeyManager, self).__init__()

        if s3_region: self.s3_region = s3_region
        if kms_region: self.kms_region = kms_region
        if sts_region: self.sts_region = sts_region
        if bucket_name: self.bucket_name = bucket_name
        if key_name: self.key_name = key_name
        if role_arn: self.role_arn = role_arm
        if role_session_name: self.role_session_name = role_session_name
        if role_external_id: self.role_external_id = role_external_id

        self.encrypted_private_key = None
        self.public_key = None
        self.role_credentials = None
        self._s3 = None
        self._kms = None
        self._sts = None
        return

    @property
    def s3(self):
        if self._s3 is None:
            self._s3 = boto.s3.connect_to_region(
                region=self.s3_region,
                aws_access_key_id=self.role_credentials.access_key,
                aws_secret_access_key=self.role_credentials.secret_key,
                security_token=self.role_credentials.security_token,
                calling_format=OrdinaryCallingFormat(),
                is_secure=True)
        return self._s3

    @property
    def kms(self):
        if self._kms is None:
            self._kms = boto.kms.connect_to_region(
                region=self.kms_region,
                aws_access_key_id=self.role_credentials.access_key,
                aws_secret_access_key=self.role_credentials.secret_key,
                security_token=self.role_credentials.security_token,
                is_secure=True)
        return self._kms

    @property
    def sts(self):
        if self._sts is None:
            self._sts = boto.sts.connect_to_region(
                region=self.sts_region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                is_secure=True)
        return self._sts


    def assume_key_manager_role(
            self, aws_access_key_id, aws_secret_access_key,
            mfa_serial_number, mfa_code):
        """
        """

        assumed_role = self.sts.assume_role(
            role_arn=self.role_arn, role_session_name=self.role_session_name,
            external_id=self.role_external_id,
            mfa_serial_number=mfa_serial_number,
            mfa_token=mfa_token)
        self.role_credentials = assumed_role.credentials
        return

    def get_private_key_from_gpg(self):
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        result, out, err = invoke("gpg", "--export-secret-keys", "--armor",
                                  suppress_output=True, return_all=True)
        if result:
            raise RuntimeError("Failed to invoke gpg: exit code %d" % result)

        plaintext_key = out
        self.encrypted_private_key = (
            self.kms.encrypt(self.key_name, plaintext_key)["CiphertextBlob"])
        return self.encrypted_private_key

    def get_public_key_from_gpg(self):
        result, out, err = invoke("gpg", "--export", "--armor",
                                  suppress_output=True, return_all=True)
        if result:
            raise RuntimeError("Failed to invoke gpg export: exit code %d" %
                               result)

        self.public_key = out
        return self.public_key

    def put_private_key_to_gpg(self):
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        plaintext = self.kms.decrypt(self.encrypted_private_key)
        result, out, err = invoke("gpg", "--import", stdin=plaintext,
                                  suppress_output=True, return_all=True)

        if result:
            raise RuntimeError("Failed to invoke gpg import: exit code %d" %
                               result)
        
        return

    def upload_private_key_to_s3(self):
        if not self.encrypted_private_key:
            raise RuntimeError("private_key not set")
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.new_key(self.key_name + ".private.enc")
        key.set_contents_from_string(
            self.encrypted_private_key, policy='private')
        return

    def download_private_key_from_s3(self):
        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.get_key(self.key_name + ".private.enc")
        self.encrypted_private_key = key.read()
        return

    def upload_public_key_to_s3(self):
        if not self.public_key:
            raise RuntimeError("public_key not set")
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.new_key(self.key_name + ".public")
        key.set_contents_from_string(
            self.public_key, policy='private')
        return

    def download_public_key_from_s3(self):
        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.get_key(self.key_name + ".public")
        self.public_key = key.read()
        return


# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
