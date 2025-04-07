import io
import re
import hashlib
from typing import Any, Iterator, List, Tuple, Union

from .helper.logging import LOGGER

from .zip import headers

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)  # Namespace as used by etree

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

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class FileNotPresent(Error):
    pass


class BrokenAPKError(Error):
    pass

class APK(object):
    def __init__(
        self,
        raw: io.BytesIO,
    ):
        self.xml = {}
        self.axml = {}
        self.arsc = {}

        self.package = ""
        self.androidversion = {}
        self.permissions = []
        self.uses_permissions = []
        self.declared_permissions = {}
        self.valid_apk = False

        self._is_signed_v2 = None
        self._is_signed_v3 = None
        self._v2_blocks = {}
        self._v2_signing_data = None
        self._v3_signing_data = None

        self._files = {}
        self.files_crc32 = {}

        self._sha256 = hashlib.sha256(raw.read()).hexdigest()
        # Set the filename to something sane
        self.filename = "raw_apk_sha256:{}".format(self._sha256)

        raw.seek(0)
        self.zip = headers.ZipEntry.parse(raw, True)

    def get_files(self) -> list[str]:
        """
        Return the file names inside the APK.

        :returns: a list of filename strings inside the APK
        """
        return self.zip.namelist()

    def get_file(self, filename: str) -> bytes:
        """
        Return the raw data of the specified filename
        inside the APK

        :param filename: the filename to get
        :raises FileNotPresent: if filename not found inside the apk
        :returns: bytes of the specified filename
        """
        try:
            return self.zip.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_dex(self) -> bytes:
        """
        Return the raw data of the classes dex file

        This will give you the data of the file called `classes.dex`
        inside the APK. If the APK has multiple DEX files, you need to use [get_all_dex][androguard.core.apk.APK.get_all_dex].

        :raises FileNotPresent: if classes.dex is not found
        :returns: the raw data of the classes dex file
        """
        try:
            return self.get_file("classes.dex")
        except FileNotPresent:
            # TODO is this a good idea to return an empty string?
            return b""

    def get_dex_names(self) -> list[str]:
        """
        Return the names of all DEX files found in the APK.
        This method only accounts for "offical" dex files, i.e. all files
        in the root directory of the APK named `classes.dex` or `classes[0-9]+.dex`

        :returns: the names of all DEX files found in the APK
        """
        dexre = re.compile(r"^classes(\d*).dex$")
        return filter(lambda x: dexre.match(x), self.get_files())

    def get_all_dex(self) -> Iterator[bytes]:
        """
        Return the raw bytes data of all classes dex files

        :returns: the raw bytes data of all classes dex files
        """
        for dex_name in self.get_dex_names():
            yield self.get_file(dex_name)

    def is_multidex(self) -> bool:
        """
        Test if the APK has multiple DEX files

        :returns: True if multiple dex found, otherwise False
        """
        dexre = re.compile(r"^classes(\d+)?.dex$")
        return (
            len(
                [
                    instance
                    for instance in self.get_files()
                    if dexre.search(instance)
                ]
            )
            > 1
        )

    def _get_crc32(self, filename):
        """
        Calculates and compares the CRC32 and returns the raw buffer.

        The CRC32 is added to [files_crc32][androguard.core.apk.APK.files_crc32] dictionary, if not present.

        :param filename: filename inside the zipfile
        :rtype: bytes
        """
        buffer = self.zip.read(filename)
        if filename not in self.files_crc32:
            self.files_crc32[filename] = crc32(buffer)
            if (
                self.files_crc32[filename]
                != self.zip.infolist()[filename].crc32_of_uncompressed_data
            ):
                logger.error(
                    "File '{}' has different CRC32 after unpacking! "
                    "Declared: {:08x}, Calculated: {:08x}".format(
                        filename,
                        self.zip.infolist()[
                            filename
                        ].crc32_of_uncompressed_data,
                        self.files_crc32[filename],
                    )
                )
        return buffer

    def get_files_crc32(self) -> dict[str, int]:
        """
        Calculates and returns a dictionary of filenames and CRC32

        :returns: dict of filename: CRC32
        """
        if self.files_crc32 == {}:
            for i in self.get_files():
                self._get_crc32(i)

        return self.files_crc32

    def get_files_information(self) -> Iterator[tuple[str, str, int]]:
        """
        Return the files inside the APK with their associated types and crc32

        :returns: the files inside the APK with their associated types and crc32
        """
        for k in self.get_files():
            yield k, self.get_files_types()[k], self.get_files_crc32()[k]
