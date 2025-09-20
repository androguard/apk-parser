import io
import os
import re

from asn1crypto import cms, keys, x509
from asn1crypto.util import OrderedDict

from struct import unpack
from hashlib import md5, sha1, sha224, sha256, sha384, sha512

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

from axml.axml import AXMLPrinter

from apkparser.helper.logging import LOGGER
from apkparser.utils import read_uint32_le
from apkparser.zip import headers

from .utils import canonical_name, parse_signatures_or_digests

class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class BrokenAPKError(Error):
    pass

# Constants in ZipFile
PK_END_OF_CENTRAL_DIR = b"\x50\x4b\x05\x06"
PK_CENTRAL_DIR = b"\x50\x4b\x01\x02"

# Constants in the APK Signature Block
APK_SIG_MAGIC = b"APK Sig Block 42"
APK_SIG_KEY_V2_SIGNATURE = 0x7109871A
APK_SIG_KEY_V3_SIGNATURE = 0xF05368C0
APK_SIG_ATTR_V2_STRIPPING_PROTECTION = 0xBEEFF00D

APK_SIG_ALGO_IDS = {
    0x0101: "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
    0x0102: "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
    0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256 digest.",  # This is for build systems which require deterministic signatures.
    0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512 digest.",  # This is for build systems which require deterministic signatures.
    0x0201: "ECDSA with SHA2-256 digest",
    0x0202: "ECDSA with SHA2-512 digest",
    0x0301: "DSA with SHA2-256 digest",
}

from .v2 import APKV2SignedData, APKV2Signer
from .v3 import APKV3SignedData, APKV3Signer


class APKSignature:
    def __init__(self, raw: io.BytesIO, files: headers.ZipEntry, axml: AXMLPrinter) -> None:
        self._raw: io.BytesIO = raw
        self._files: headers.ZipEntry = files
        self._axml: AXMLPrinter = axml

        self._is_signed_v2 = False
        self._is_signed_v3 = False
        self._v2_blocks = {}
        self._v2_signing_data = None
        self._v3_signing_data = None

        self.parse_v2_v3_signature()


    def is_signed(self) -> bool:
        """
        Returns true if any of v1, v2, or v3 signatures were found.

        :returns: True if any of v1, v2, or v3 signatures were found, else False
        """
        return (
            self.is_signed_v1() or self.is_signed_v2() or self.is_signed_v3()
        )

    def is_signed_v1(self) -> bool:
        """
        Returns `True` if a v1 / JAR signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.

        :returns: `True` if a v1 / JAR signature was found, else `False`
        """
        return self.get_signature_name() is not None

    def is_signed_v2(self) -> bool:
        """
        Returns `True` of a v2 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.

        :returns: `True` of a v2 / APK signature was found, else `False`
        """
        return self._is_signed_v2

    def is_signed_v3(self) -> bool:
        """
        Returns `True` of a v3 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.

        :returns: `True` of a v3 / APK signature was found, else `False`
        """
        return self._is_signed_v3
    
    def parse_v2_v3_signature(self) -> None:
        # Need to find an v2 Block in the APK.
        # The Google Docs gives you the following rule:
        # * go to the end of the ZIP File
        # * search for the End of Central directory
        # * then jump to the beginning of the central directory
        # * Read now the magic of the signing block
        # * before the magic there is the size_of_block, so we can jump to
        # the beginning.
        # * There should be again the size_of_block
        # * Now we can read the Key-Values
        # * IDs with an unknown value should be ignored.
        f = self._raw

        _size_central = None
        offset_central = None

        # Go to the end
        f.seek(-1, io.SEEK_END)
        # we know the minimal length for the central dir is 16+4+2
        f.seek(-20, io.SEEK_CUR)

        while f.tell() > 0:
            f.seek(-1, io.SEEK_CUR)
            (r,) = unpack('<4s', f.read(4))
            if r == PK_END_OF_CENTRAL_DIR:
                # Read central dir
                (
                    this_disk,
                    disk_central,
                    _this_entries,
                    _total_entries,
                    _size_central,
                    offset_central,
                ) = unpack('<HHHHII', f.read(16))
                # TODO according to the standard we need to check if the
                # end of central directory is the last item in the zip file
                # TODO We also need to check if the central dir is exactly
                # before the end of central dir...

                # These things should not happen for APKs
                if this_disk != 0:
                    LOGGER.warning(
                        "This is a multi disk ZIP! Attempting to process its signature anyway!"
                    )
                if disk_central != 0:
                    LOGGER.warning(
                        "This is a multi disk ZIP! Attempting to process its signature anyway!"
                    )
                break
            f.seek(-4, io.SEEK_CUR)

        if not offset_central:
            return

        f.seek(offset_central)
        (r,) = unpack('<4s', f.read(4))
        f.seek(-4, io.SEEK_CUR)
        if r != PK_CENTRAL_DIR:
            raise BrokenAPKError("No Central Dir at specified offset")

        # Go back and check if we have a magic
        end_offset = f.tell()
        f.seek(-24, io.SEEK_CUR)
        size_of_block, magic = unpack('<Q16s', f.read(24))

        self._is_signed_v2 = False
        self._is_signed_v3 = False

        if magic != APK_SIG_MAGIC:
            return

        # go back size_of_blocks + 8 and read size_of_block again
        f.seek(-(size_of_block + 8), io.SEEK_CUR)
        (size_of_block_start,) = unpack("<Q", f.read(8))
        if size_of_block_start != size_of_block:
            raise BrokenAPKError("Sizes at beginning and end does not match!")

        # Store all blocks
        while f.tell() < end_offset - 24:
            size, key = unpack('<QI', f.read(12))
            value = f.read(size - 4)
            if key in self._v2_blocks:
                # TODO: Store the duplicate V2 Signature blocks and offer a way to show them
                # https://github.com/androguard/androguard/issues/1030
                LOGGER.warning(
                    "Duplicate block ID in APK Signing Block: {}".format(key)
                )
            else:
                self._v2_blocks[key] = value

        # Test if a signature is found
        if APK_SIG_KEY_V2_SIGNATURE in self._v2_blocks:
            self._is_signed_v2 = True

        if APK_SIG_KEY_V3_SIGNATURE in self._v2_blocks:
            self._is_signed_v3 = True

    def parse_v3_signing_block(self) -> None:
        """
        Parse the V3 signing block and extract all features
        """
        self._v3_signing_data = []

        # calling is_signed_v3 should also load the signature, if any
        if not self.is_signed_v3():
            return

        block_bytes = self._v2_blocks[APK_SIG_KEY_V3_SIGNATURE]
        block = io.BytesIO(block_bytes)
        view = block.getvalue()

        # V3 signature Block data format:
        #
        # * signer:
        #    * signed data:
        #        * digests:
        #            * signature algorithm ID (uint32)
        #            * digest (length-prefixed)
        #        * certificates
        #        * minSDK
        #        * maxSDK
        #        * additional attributes
        #    * minSDK
        #    * maxSDK
        #    * signatures
        #    * publickey
        size_sequence = read_uint32_le(block)
        if size_sequence + 4 != len(block_bytes):
            raise BrokenAPKError(
                "size of sequence and blocksize does not match"
            )

        while block.tell() < len(block_bytes):
            off_signer = block.tell()
            size_signer = read_uint32_le(block)

            # read whole signed data, since we might to parse
            # content within the signed data, and mess up offset
            len_signed_data = read_uint32_le(block)
            signed_data_bytes = block.read(len_signed_data)
            signed_data = io.BytesIO(signed_data_bytes)

            # Digests
            len_digests = read_uint32_le(signed_data)
            raw_digests = signed_data.read(len_digests)
            digests = parse_signatures_or_digests(raw_digests)

            # Certs
            certs = []
            len_certs = read_uint32_le(signed_data)
            start_certs = signed_data.tell()
            while signed_data.tell() < start_certs + len_certs:

                len_cert = read_uint32_le(signed_data)
                cert = signed_data.read(len_cert)
                certs.append(cert)

            # versions
            signed_data_min_sdk = read_uint32_le(signed_data)
            signed_data_max_sdk = read_uint32_le(signed_data)

            # Addional attributes
            len_attr = read_uint32_le(signed_data)
            attr = signed_data.read(len_attr)

            signed_data_object = APKV3SignedData()
            signed_data_object._bytes = signed_data_bytes
            signed_data_object.digests = digests
            signed_data_object.certificates = certs
            signed_data_object.additional_attributes = attr
            signed_data_object.minSDK = signed_data_min_sdk
            signed_data_object.maxSDK = signed_data_max_sdk

            # versions (should be the same as signed data's versions)
            signer_min_sdk = read_uint32_le(block)
            signer_max_sdk = read_uint32_le(block)

            # Signatures
            len_sigs = read_uint32_le(block)
            raw_sigs = block.read(len_sigs)
            sigs = parse_signatures_or_digests(raw_sigs)

            # PublicKey
            len_publickey = read_uint32_le(block)
            publickey = block.read(len_publickey)

            signer = APKV3Signer()
            signer._bytes = view[off_signer : off_signer + size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey
            signer.minSDK = signer_min_sdk
            signer.maxSDK = signer_max_sdk

            self._v3_signing_data.append(signer)


    def parse_v2_signing_block(self) -> None:
        """
        Parse the V2 signing block and extract all features
        """

        self._v2_signing_data = []

        # calling is_signed_v2 should also load the signature
        if not self.is_signed_v2():
            return

        block_bytes = self._v2_blocks[APK_SIG_KEY_V2_SIGNATURE]
        block = io.BytesIO(block_bytes)
        view = block.getvalue()

        # V2 signature Block data format:
        #
        # * signer:
        #    * signed data:
        #        * digests:
        #            * signature algorithm ID (uint32)
        #            * digest (length-prefixed)
        #        * certificates
        #        * additional attributes
        #    * signatures
        #    * publickey

        size_sequence = read_uint32_le(block)
        if size_sequence + 4 != len(block_bytes):
            raise BrokenAPKError(
                "size of sequence and blocksize does not match"
            )

        while block.tell() < len(block_bytes):
            off_signer = block.tell()
            size_signer = read_uint32_le(block)

            # read whole signed data, since we might to parse
            # content within the signed data, and mess up offset
            len_signed_data = read_uint32_le(block)
            signed_data_bytes = block.read(len_signed_data)
            signed_data = io.BytesIO(signed_data_bytes)

            # Digests
            len_digests = read_uint32_le(signed_data)
            raw_digests = signed_data.read(len_digests)
            digests = parse_signatures_or_digests(raw_digests)

            # Certs
            certs = []
            len_certs = read_uint32_le(signed_data)
            start_certs = signed_data.tell()
            while signed_data.tell() < start_certs + len_certs:
                len_cert = read_uint32_le(signed_data)
                cert = signed_data.read(len_cert)
                certs.append(cert)

            # Additional attributes
            len_attr = read_uint32_le(signed_data)
            attributes = signed_data.read(len_attr)

            signed_data_object = APKV2SignedData()
            signed_data_object._bytes = signed_data_bytes
            signed_data_object.digests = digests
            signed_data_object.certificates = certs
            signed_data_object.additional_attributes = attributes

            # Signatures
            len_sigs = read_uint32_le(block)
            raw_sigs = block.read(len_sigs)
            sigs = parse_signatures_or_digests(raw_sigs)

            # PublicKey
            len_publickey = read_uint32_le(block)
            publickey = block.read(len_publickey)

            signer = APKV2Signer()
            signer._bytes = view[off_signer : off_signer + size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey

            self._v2_signing_data.append(signer)

    def get_public_keys_der_v3(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 public keys from the v3 signature block

        :returns: the list of public key bytes
        """

        if self._v3_signing_data == None:
            self.parse_v3_signing_block()

        public_keys = []

        for signer in self._v3_signing_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_public_keys_der_v2(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 public keys from the v3 signature block

        :returns: the list of public key bytes
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        public_keys = []

        for signer in self._v2_signing_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_certificates_der_v3(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 certificates from the v3 signature block

        :returns: the list of public key bytes
        """

        if self._v3_signing_data == None:
            self.parse_v3_signing_block()

        certs = []
        for signed_data in [
            signer.signed_data for signer in self._v3_signing_data
        ]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_certificates_der_v2(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 certificates from the v3 signature block

        :returns: the list of public key bytes
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        certs = []
        for signed_data in [
            signer.signed_data for signer in self._v2_signing_data
        ]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_public_keys_v3(self) -> list[keys.PublicKeyInfo]:
        """
        Return a list of `asn1crypto.keys.PublicKeyInfo` which are found
        in the v3 signing block.

        :returns: a list of the found `asn1crypto.keys.PublicKeyInfo`
        """
        return [
            keys.PublicKeyInfo.load(pkey)
            for pkey in self.get_public_keys_der_v3()
        ]

    def get_public_keys_v2(self) -> list[keys.PublicKeyInfo]:
        """
        Return a list of `asn1crypto.keys.PublicKeyInfo` which are found
        in the v2 signing block.

        :returns: a list of the found `asn1crypto.keys.PublicKeyInfo`
        """
        return [
            keys.PublicKeyInfo.load(pkey)
            for pkey in self.get_public_keys_der_v2()
        ]

    def get_certificates_v3(self) -> list[x509.Certificate]:
        """
        Return a list of `asn1crypto.x509.Certificate` which are found
        in the v3 signing block.
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.

        :returns: a list of the found `asn1crypto.x509.Certificate`
        """
        return [
            x509.Certificate.load(cert)
            for cert in self.get_certificates_der_v3()
        ]

    def get_certificates_v2(self) -> list[x509.Certificate]:
        """
        Return a list of `asn1crypto.x509.Certificate` which are found
        in the v2 signing block.
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.

        :returns: a list of the found `asn1crypto.x509.Certificate`
        """
        return [
            x509.Certificate.load(cert)
            for cert in self.get_certificates_der_v2()
        ]

    def get_certificates_v1(self) -> list[x509.Certificate]:
        """
        Return a list of verified `asn1crypto.x509.Certificate` which are found
        in the META-INF folder (v1 signing).
        """
        certs = []
        for x in self.get_signature_names():
            cc = self.get_certificate_der(x)
            if cc is not None:
                certs.append(x509.Certificate.load(cc))
        return certs

    def get_certificates(self) -> list[x509.Certificate]:
        """
        Return a list of unique `asn1crypto.x509.Certificate` which are found
        in v1, v2 and v3 signing
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        Exception is v1, for which the certificate returned is verified.
        
        :returns: a list of the found `asn1crypto.x509.Certificate`
        """
        fps = []
        certs = []
        for x in (
            self.get_certificates_v1()
            + self.get_certificates_v2()
            + self.get_certificates_v3()
        ):
            if x.sha256 not in fps:
                fps.append(x.sha256)
                certs.append(x)
        return certs

    def get_signature_name(self) -> list[str]|None:
        """
        Return the name of the first signature file found.

        :returns: the name of the first signature file, or `None` if not signed
        """
        if self.get_signature_names():
            return self.get_signature_names()[0]
        else:
            # Unsigned APK
            return None

    def get_signature_names(self) -> list[str]:
        """
        Return a list of the signature file names (v1 Signature / JAR
        Signature)

        :returns: List of filenames matching a Signature
        """
        signature_expr = re.compile(r'\AMETA-INF/(?s:.)*\.(DSA|EC|RSA)\Z')
        signatures = []

        for i in self._files.namelist():
            if signature_expr.search(i):
                if "{}.SF".format(i.rsplit(".", 1)[0]) in self._files.namelist():
                    signatures.append(i)
                else:
                    LOGGER.warning(
                        "v1 signature file {} missing .SF file - Partial signature!".format(
                            i
                        )
                    )

        return signatures

    def get_signature(self) -> list[bytes]|None:
        """
        Return the data of the first signature file found (v1 Signature / JAR
        Signature)

        :returns: First signature name or None if not signed
        """
        if self.get_signatures():
            return self.get_signatures()[0]
        else:
            return None

    def get_signatures(self) -> list[bytes]:
        """
        Return a list of the data of the signature files.
        Only v1 / JAR Signing.

        :returns: list of bytes
        """
        signature_expr = re.compile(r'\AMETA-INF/(?s:.)*\.(DSA|EC|RSA)\Z')
        signature_datas = []

        for i in self._files.namelist():
            if signature_expr.search(i):
                signature_datas.append(self._files.read(i))

        return signature_datas
    

    def get_certificate_der(
        self, filename: str, max_sdk_version: int = -1
    ) -> bytes|None:
        """
        Return the DER coded X.509 certificate from the signature file.
        If minSdkVersion is prior to Android N only the first SignerInfo is used.
        If signed attributes are present, they are taken into account
        Note that unsupported critical extensions and key usage are not verified!
        [V1SchemeVerifier.java](https://android.googlesource.com/platform/tools/apksig/+/refs/tags/platform-tools-34.0.5/src/main/java/com/android/apksig/internal/apk/v1/V1SchemeVerifier.java#668)

        :param filename: Signature filename in APK
        :param max_sdk_version: An optional integer parameter for the max sdk version
        :returns: DER coded X.509 certificate as binary or None
        """

        # Get the signature
        pkcs7message = self._files.read(filename)
        # Get the .SF
        sf_filename = os.path.splitext(filename)[0] + '.SF'
        sf_object = self._files.read(sf_filename)
        # Load the signature
        signed_data = cms.ContentInfo.load(pkcs7message)
        # Locate the SignerInfo structure
        signer_infos = signed_data['content']['signer_infos']
        if not signer_infos:
            LOGGER.error(
                'No signer information found in the PKCS7 object. The APK may not be properly signed.'
            )
            return None

        # Prior to Android N, Android attempts to verify only the first SignerInfo. From N onwards, Android attempts
        # to verify all SignerInfos and then picks the first verified SignerInfo.
        min_sdk_version = self._axml.get_min_sdk_version()
        if (
            min_sdk_version is None or int(min_sdk_version) < 24
        ):  # AndroidSdkVersion.N
            LOGGER.info(
                f"minSdkVersion: {min_sdk_version} is less than 24. Getting the first signerInfo only!"
            )
            unverified_signer_infos_to_try = [signer_infos[0]]
        else:
            unverified_signer_infos_to_try = signer_infos

        # Extract certificates from the PKCS7 object
        certificates = signed_data['content']['certificates']
        return_certificate = None
        list_certificates_verified = []
        for signer_info in unverified_signer_infos_to_try:
            try:
                matching_certificate_verified = (
                    self.verify_signer_info_against_sig_file(
                        signed_data,
                        certificates,
                        signer_info,
                        sf_object,
                        max_sdk_version,
                    )
                )
            except (ValueError, TypeError, OSError, InvalidSignature) as e:
                LOGGER.error(
                    f"The following exception was raised while verifying the certificate: {e}"
                )
                return (
                    None  # the validation stops due to the exception raised!
                )
            if matching_certificate_verified is not None:
                list_certificates_verified.append(
                    matching_certificate_verified
                )
        if not list_certificates_verified:
            LOGGER.error(
                f"minSdkVersion: {min_sdk_version}, # of SignerInfos: {len(unverified_signer_infos_to_try)}. None Verified!"
            )
        else:
            return_certificate = list_certificates_verified[0]
        return return_certificate

    def verify_signer_info_against_sig_file(
        self,
        signed_data: cms.ContentInfo,
        certificates: cms.CertificateSet,
        signer_info: cms.SignerInfo,
        sf_object: str,
        max_sdk_version: int|None=None,
    ) -> bytes|None:
        matching_certificate = self.find_certificate(certificates, signer_info)
        matching_certificate_verified = None
        digest_algorithm, crypto_hash_algorithm = self.get_hash_algorithm(
            signer_info
        )
        if matching_certificate is None:
            raise ValueError(
                "Signing certificate referenced in SignerInfo not found in SignedData"
            )
        else:
            if signer_info['signed_attrs'].native:
                LOGGER.info("Signed Attributes detected!")
                signed_attrs = signer_info['signed_attrs']
                signed_attrs_dict = OrderedDict()
                for attr in signed_attrs:
                    if attr['type'].dotted in signed_attrs_dict:
                        raise ValueError(
                            f"Duplicate signed attribute: {attr['type'].dotted}"
                        )
                    signed_attrs_dict[attr['type'].dotted] = attr['values']

                # Check content type attribute (for Android N and newer)
                if max_sdk_version is None or int(max_sdk_version) >= 24:
                    content_type_oid = (
                        '1.2.840.113549.1.9.3'  # OID for contentType
                    )
                    if content_type_oid not in signed_attrs_dict:
                        raise ValueError(
                            "No Content Type in signed attributes"
                        )
                    content_type = signed_attrs_dict[content_type_oid][
                        0
                    ].native
                    if (
                        content_type
                        != signed_data['content']['encap_content_info'][
                            'content_type'
                        ].native
                    ):
                        LOGGER.error(
                            "Content Type mismatch. Continuing to next SignerInfo, if any."
                        )
                        return None

                # Check message digest attribute
                message_digest_oid = (
                    '1.2.840.113549.1.9.4'  # OID for messageDigest
                )
                if message_digest_oid not in signed_attrs_dict:
                    raise ValueError("No content digest in signed attributes")
                expected_signature_file_digest = signed_attrs_dict[
                    message_digest_oid
                ][0].native
                hash_algo = digest_algorithm()
                hash_algo.update(sf_object)
                actual_digest = hash_algo.digest()

                # Compare digests
                if actual_digest != expected_signature_file_digest:
                    LOGGER.error(
                        "Digest mismatch. Continuing to next SignerInfo, if any."
                    )
                    return None

                signed_attrs_dump = signed_attrs.dump()
                # Modify the first byte to 0x31 for UNIVERSAL SET
                signed_attrs_dump = b'\x31' + signed_attrs_dump[1:]
                matching_certificate_verified = self.verify_signature(
                    signer_info,
                    matching_certificate,
                    signed_attrs_dump,
                    crypto_hash_algorithm,
                )
            else:
                matching_certificate_verified = self.verify_signature(
                    signer_info,
                    matching_certificate,
                    sf_object,
                    crypto_hash_algorithm,
                )
        return matching_certificate_verified

    @staticmethod
    def verify_signature(
        signer_info: cms.SignerInfo,
        matching_certificate,
        signed_data,
        crypto_hash_algorithm
    ) -> bytes:
        matching_certificate_verified = None
        signature = signer_info['signature'].native

        # Load the certificate using asn1crypto as it can handle more cases (v1-only-with-rsa-1024-cert-not-der.apk)
        cert = x509.Certificate.load(matching_certificate.chosen.dump())
        public_key_info = cert.public_key

        # Convert the ASN.1 public key to a cryptography-compatible object
        public_key_der = public_key_info.dump()
        public_key = serialization.load_der_public_key(
            public_key_der, backend=default_backend()
        )

        try:
            # RSA Key
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    signed_data,
                    padding.PKCS1v15(),
                    crypto_hash_algorithm(),
                )

            # DSA Key
            elif isinstance(public_key, dsa.DSAPublicKey):
                public_key.verify(
                    signature, signed_data, crypto_hash_algorithm()
                )

            # EC Key
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature, signed_data, ec.ECDSA(crypto_hash_algorithm())
                )

            else:
                raise ValueError(
                    f"Unsupported key algorithm: {public_key.__class__.__name__.lower()}"
                )

            # If verification succeeds, return the certificate
            matching_certificate_verified = matching_certificate.chosen.dump()

        except InvalidSignature:
            LOGGER.info(
                f"The public key of the certificate: {hashlib.sha256(matching_certificate.chosen.dump()).hexdigest()} "
                f"is not associated with the signature!"
            )

        return matching_certificate_verified

    @staticmethod
    def get_hash_algorithm(signer_info: cms.SignerInfo) -> dict[str, hashes.HashAlgorithm]:
        # Determine the hash algorithm from the SignerInfo
        digest_algorithm = signer_info['digest_algorithm']['algorithm'].native
        # Map the digest algorithm to a hash function
        hash_algorithms = {
            'md5': (md5, hashes.MD5),
            'sha1': (sha1, hashes.SHA1),
            'sha224': (sha224, hashes.SHA224),
            'sha256': (sha256, hashes.SHA256),
            'sha384': (sha384, hashes.SHA384),
            'sha512': (sha512, hashes.SHA512),
        }
        if digest_algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {digest_algorithm}")
        return hash_algorithms[digest_algorithm]

    def find_certificate(
        self,
        signed_data_certificates: cms.CertificateSet,
        signer_info: cms.SignerInfo) -> x509.Certificate|None:
        """
        From the bag of certs, obtain the certificate referenced by the `asn1crypto.cms.SignerInfo`.

        :param signed_data_certificates: List of certificates in the SignedData.
        :param signer_info: `SignerInfo` object containing the issuer and serial number reference.

        :returns: The matching certificate if found, otherwise None.
        """
        matching_certificate = None
        issuer_and_serial_number = signer_info['sid']
        issuer_str = canonical_name(
            issuer_and_serial_number.chosen['issuer']
        )
        serial_number = issuer_and_serial_number.native['serial_number']

        # # Create a x509.Name object for the issuer in the SignerInfo
        # issuer_name = x509.Name.build(issuer)
        # issuer_str = self.canonical_name(issuer_name)

        for cert in signed_data_certificates:
            if cert.name == 'certificate':
                cert_issuer = canonical_name(
                    cert.chosen['tbs_certificate']['issuer']
                )
                cert_serial_number = cert.native['tbs_certificate'][
                    'serial_number'
                ]

                # Compare the canonical string representations of the issuers and the serial numbers
                if (
                    cert_issuer == issuer_str
                    and cert_serial_number == serial_number
                ):
                    matching_certificate = cert
                    break

        return matching_certificate

    def get_certificate(self, filename: str) -> x509.Certificate|None:
        """
        Return a X.509 certificate object by giving the name in the apk file

        :param filename: filename of the signature file in the APK
        :returns: the certificate object
        """
        cert = self.get_certificate_der(filename)
        if cert:
            certificate = x509.Certificate.load(cert)
        else:
            certificate = None
        return certificate
