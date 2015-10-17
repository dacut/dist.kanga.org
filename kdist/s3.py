#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from base64 import b64decode, b64encode
from boto.exception import BotoServerError
from Crypto.Cipher import AES
import Crypto.Random
from json import dumps as json_dumps, loads as json_loads

AES_BLOCKSIZE = 16
_AES_256 = "AES_256"
_AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding"
_CiphertextBlob = "CiphertextBlob"
_KeyId = "KeyId"
_Plaintext = "Plaintext"
_kms = "kms"
_kms_cmk_id = "kms_cmk_id"
_x_amz_cek_alg = "x-amz-cek-alg"
_x_amz_iv = "x-amz-iv"
_x_amz_key_v2 = "x-amz-key-v2"
_x_amz_matdesc = "x-amz-matdesc"
_x_amz_meta_ = "x-amz-meta-"
_x_amz_wrap_alg = "x-amz-wrap-alg"

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

        plaintext_data = cipher.decrypt(encrypted_data)

        if cek_alg in (_AES_CBC_PKCS5Padding,):
            plaintext_data = plaintext_data[:-ord(plaintext_data[-1])]

        return plaintext_data

    def write(self, key, plaintext_data, wrapper_algorithm=_kms,
              encryption_algorithm=_AES_CBC_PKCS5Padding, key_id=None,
              headers=None, **kw):
        key_name = "s3://%s/%s" % (key.bucket.name, key.name)
        random = Crypto.Random.new()

        # Encryption metadata headers for the S3 object
        s3_headers = {
            _x_amz_meta_ + _x_amz_wrap_alg: wrapper_algorithm,
            _x_amz_meta_ + _x_amz_cek_alg: encryption_algorithm,
        }
        
        # Create a cipher and pad the metadata as needed.
        if encryption_algorithm in (_AES_CBC_PKCS5Padding,):
            # Create an IV; needed to scramble the data.
            iv = random.read(16)
            s3_headers[_x_amz_meta_ + _x_amz_iv] = b64encode(iv)

            if wrapper_algorithm == _kms:
                # Call KMS to generate a data key
                encryption_context = { _kms_cmk_id: key_id }
                try:
                    dk_result = self.kms.generate_data_key(
                        key_id=self.key_id,
                        encryption_context=encryption_context,
                        key_spec=_AES_256)
                except BotoServerError as e:
                    raise EncryptionError(
                        "%s: failed to generate data key from KMS: %s" %
                        (key_name, e))

                # This is our data encryption key.
                data_key = dk_result[_Plaintext]

                # This is our data encryption key, itself encrypted with
                # the customer master key.
                ciphertext_blob = dk_result[_CiphertextBlob]
                s3_headers[_x_amz_meta_ + _x_amz_key_v2] = b64encode(
                    ciphertext_blob)

                # Record the key used to encrypt the data.
                s3_headers[_x_amz_meta_ + _x_amz_matdesc] = json_dumps(
                    {_kms_cmk_id: dk_result[_KeyId]})
            else:
                raise EncryptionError(
                    "%s: Unsupported wrapper algorithm %r" %
                    (key_name, wrapper_algorithm))

            # Pad the data out to the AES blocksize.
            pad = AES_BLOCKSIZE - len(plaintext_data) % AES_BLOCKSIZE
            plaintext_data = plaintext_data + chr(pad) * pad
            cipher = AES.new(data_key, AES.MODE_CBC, iv)
        else:
            raise EncryptionError(
                "%s: Unknown encryption algorithm %s" %
            (key_name, encryption_algorithm))
        
        if headers is not None:
            s3_headers.update(headers)

        encrypted_data = cipher.encrypt(plaintext_data)
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
