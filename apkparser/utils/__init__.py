import io
import struct

class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class BrokenAPKError(Error):
    pass

def read_uint32_le(io_stream: io.BytesIO) -> int:
    """read a `uint32_le` from `io_stream`
    
    :param io_stream: the stream to get a `uint32_le` from
    :return: the `uint32_le` value
    """
    (value,) = struct.unpack('<I', io_stream.read(4))
    return value

def is_android(filename: str) -> str:
    """
    Return the type of the file

    :param filename: the filename
    :returns: "APK", "APKM", "DEX", None
    """
    if not filename:
        return None

    with open(filename, "rb") as fd:
        f_bytes = fd.read()
        return is_android_raw(f_bytes)


def is_android_raw(raw: bytes) -> str:
    """
    Returns a string that describes the type of file, for common Android
    specific formats

    :param raw: the file bytes to check
    :returns: the type of file
    """
    val = None

    # We do not check for META-INF/MANIFEST.MF,
    # as you also want to analyze unsigned APKs...
    # AndroidManifest.xml should be in every APK.
    # classes.dex and resources.arsc are not required!
    # if raw[0:2] == b"PK" and b'META-INF/MANIFEST.MF' in raw:
    # TODO this check might be still invalid. A ZIP file with stored APK inside would match as well.
    # Prefer APKM (split container) before plain APK: nested base.apk often contains
    # the string AndroidManifest.xml in its payload.
    if raw[0:2] == b"PK" and _looks_like_apkm(raw):
        val = "APKM"
    elif raw[0:2] == b"PK" and b'AndroidManifest.xml' in raw:
        val = "APK"
        # check out
    elif raw[0:3] == b"dex":
        val = "DEX"
    elif raw[0:3] == b"dey":
        val = "DEY"
    elif raw[0:4] == b"\x03\x00\x08\x00" or raw[0:4] == b"\x00\x00\x08\x00":
        val = "AXML"
    elif raw[0:4] == b"\x02\x00\x0C\x00":
        val = "ARSC"

    return val


def _looks_like_apkm(raw: bytes) -> bool:
    """True for APKMirror-style ZIP with base.apk and no root AndroidManifest.xml."""
    try:
        import zipfile
        import io
        zf = zipfile.ZipFile(io.BytesIO(raw))
        names = zf.namelist()
    except Exception:
        return False
    if "AndroidManifest.xml" in names:
        return False
    lower_files = [n.rsplit("/", 1)[-1].lower() for n in names]
    if "base.apk" in lower_files:
        return True
    apks = [n for n in names if n.rsplit("/", 1)[-1].lower().endswith(".apk")]
    return len(apks) >= 1 and "AndroidManifest.xml" not in names


def unwrap_apkm_to_apk_bytes(raw: bytes) -> bytes:
    """If `raw` is APKM, return base.apk bytes; if APK, return raw unchanged."""
    if is_android_raw(raw) != "APKM":
        return raw
    import zipfile
    import io
    zf = zipfile.ZipFile(io.BytesIO(raw))
    names = zf.namelist()
    base = next(
        (n for n in names if n.rsplit("/", 1)[-1].lower() == "base.apk"),
        None,
    )
    if base is None:
        apks = [n for n in names if n.rsplit("/", 1)[-1].lower().endswith(".apk")]
        if len(apks) != 1:
            raise BrokenAPKError("APKM missing base.apk")
        base = apks[0]
    return zf.read(base)