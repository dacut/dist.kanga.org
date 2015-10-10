#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from base64 import b64decode, b64encode
from boto.exceptions import BotoServerError
from Crypto.Cipher import AES
import Crypto.Random
from json import loads as json_loads

_kms = "kms"
_kms_cmk_id = "kms_cmk_id"
_x_amz_wrap_alg = "x-amz-wrap-alg"
_x_amz_matdesc = "x-amz-matdesc"
_x_amz_key_v2 = "x-amz-key-v2"
_x_amz_iv = "x-amz-iv"
_x_amz_cek_alg = "x-amz-cek-alg"
_x_amz_meta_ = "x-amz-meta-"
_AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding"

class EncryptionError(RuntimeError):
    """
    Exception raised if an error occurs during an S3 encryption or 
    decryption operation.
    """
    pass

class S3ClientEncryptionHandler(object):
    """
    When stored in S3, the following metadata is stored on the object 
    (and is compatible with the Java SDK):
        x-amz-cek-alg   The algorithm used to encrypt.  This must be
                        "AES/CBC/PKCS5Padding".
        x-amz-iv        The initialization vector (IV) used to encrypt the
                        file, base-64 encoded
        x-amz-key-v2    The AES-256 key used to encrypt the file, itself
                        encrypted with KMS (ciphertext blob) and base-64
                        encoded.
        x-amz-matdesc   JSON object with a property, "kms_cmk_id", identifying
                        the KMS customer master key id.  This is used as the
                        encryption context to KMS.
        x-amz-wrap-alg  The wrapper used to encrypt the key.  This must be
                        "kms".

    """
    def __init__(self, kms, key_id=None):
        super(S3ClientEncryptionHandler, self).__init__()
        self.kms = kms
        self.key_id = key_id
        return
    
    def read(self, key):
        encrypted_data = key.read()
        wrapper_alg = key.get_metadata(_x_amz_wrap_alg)
        material_desc = key.get_metadata(_x_amz_matdesc)
        encrypted_data_key = key.get_metadata(_x_amz_key_v2)
        iv = key.get_metadata(_x_amz_iv)
        cek_alg = key.get_metadata(_x_amz_cek_alg)

        key_name = "s3://%s/%s" % (key.bucket.name, key.name)

        if encrypted_data_key is None:
            raise EncryptionError(
                "%s: Missing %s metadata entry" % (key_name, _x_amz_key_v2))

        try:
            encrypted_data_key = b64decode(encrypted_data_key)
        except ValueError:
            raise EncryptionError(
                "%s: Malformed %s metadata entry" % (key_name, _x_amz_key_v2))

        if wrapper_alg == _kms:
            data_key = self.decrypt_data_key_kms(
                key_name, encrypted_data_key, material_desc)
        else:
            raise EncryptionError(
                "%s: Unrecognized wrapper %s" % (key_name, wrapper_alg))

        if cek_alg == _AES_CBC_PKCS5Padding:
            if iv is None:
                raise EncryptionError(
                    "%s: Missing %s metadata entry" % (key_name, _x_amz_iv))
            iv = b64decode(iv)
            cipher = AES.new(data_key, AES.MODE_CBC, iv)
        else:
            raise EncryptionError(
                "%s: Unknown cipher %s" % (key_name, cek_alg))

        plaintext_data = ciper.decrypt(encrypted_data)

        if cek_alg in (_AES_CBC_PKCS5Padding,):
            plaintext_data = plaintext_data[:-ord(plaintext_data[-1])]

        return plaintext_data

    def write(self, key, plaintext_data, wrapper_algorithm=_kms,
              encryption_algorithm=_AES_CBC_PKCS5, key_id=None, headers=None,
              **kw):
        key_name = "s3://%s/%s" % (key.bucket.name, key.name)
        random = Crypto.Random.new()

        # Encryption metadata headers for the S3 object
        s3_headers = {
            _x_amz_meta_ + _x_amz_wrap_alg: wrapper_alg,
            _x_amz_meta_ + _x_amz_cek_alg: encryption_algorithm,
        }
        
        # Create a cipher and pad the metadata as needed.
        if encryption_algorithm in (_AES_CBC_PKCS5,):
            data_key = random.read(16)
            iv = random.read(16)
            pad = 16 - len(plaintext_data) % 16
            plaintext_data = plaintext_data + chr(pad) * pad
            cipher = AES.new(data_key, AES.MODE_CBC, iv)

            s3_headers[_x_amz_meta_ + _x_amz_iv] = b64encode(iv)
        else:
            raise EncryptionError(
                "%s: Unknown encryption algorithm %s" %
                (key_name, encryption_algorithm))
        
        encrypted_data = cipher.encrypt(plaintext_data)

        # Encrypt the data key.
        if wrapper_algorithm == _kms:
            if key_id is None:
                key_id = self.key_id
                if key_id is None:
                    raise EncryptionError(
                        "%s: Must specify a key_id or set a default for KMS "
                        "encryption" % key_name)

            encryption_context = { _kms_cmk_id: key_id }
            try:
                response = self.kms.encrypt(
                    key_id, data_key, encryption_context=encryption_context)
                encrypted_data_key = response['CiphertextBlob']
            except BotoServerError as e:
                raise EncryptionError(
                    "%s: KMS encryption failure: %s" % (key_name, e))

            s3_headers[_x_amz_meta_ + _x_amz_matdesc] = (
                json_dumps(encryption_context))
        else:
            raise EncryptionError(
                "%s: Unsupported wrapper algorithm %r" %
                (key_name, wrapper_algorithm))

        s3_headers[_x_amz_meta_ + _x_amz_key_v2] = (
            b64encode(encrypted_data_key))

        if headers is not None:
            s3_headers.update(headers)
        
        key.set_contents_from_string(encrypted_data, headers=s3_headers, **kw)
        return

    def decrypt_data_key_kms(self, key_name, encrypted_data_key, material_desc):
        if material_desc is None:
            raise EncryptionError("%s: Missing %s metadata entry" %
                                  (key_name, _x_amz_matdesc))

        try:
            material_desc = json_loads(material_desc)
        except ValueError:
            raise EncryptionError(
                "%s: Metadata entry %s is not valid JSON" %
                (key_name, _x_amz_matdesc))
        
        cmk_id = material_desc.get(_kms_cmk_id)
        if cmk_id is None:
            raise EncryptionError(
                "%s: metadata entry %s does not have a %s key" %
                (key_name, _x_amz_matdesc, _kms_cmk_id))

        try:
            decrypt_response = self.kms.decrypt(
                encrypted_data_key, encryption_context=material_desc)
            return decrypt_response['Plaintext']
        except BotoServerError as e:
            raise EncryptionError(
                "%s: KMS decryption failure: %s" % (key_name, e))

        
            
        
        
# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
