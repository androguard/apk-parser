import io
import binascii
import unicodedata
import re

from asn1crypto.x509 import Name
from asn1crypto import cms, keys, x509

from apkparser.utils import read_uint32_le


def parse_signatures_or_digests(
    digest_bytes: bytes
) -> list[tuple[int, bytes]]:
    """Parse digests
    
    :param digest_bytes: the digests bytes
    :returns: a list of tuple where the first element is the `algorithm_id` and the second is the digest bytes
    """
    
    if not len(digest_bytes):
        return []

    digests = []
    block = io.BytesIO(digest_bytes)

    data_len = read_uint32_le(block)
    while block.tell() < data_len:

        algorithm_id = read_uint32_le(block)
        digest_len = read_uint32_le(block)
        digest = block.read(digest_len)

        digests.append((algorithm_id, digest))

    return digests

def get_certificate_name_string(
    name: dict|Name, short: bool = False, delimiter: str = ', '
) -> str:
    """
    Format the Name type of a X509 Certificate in a human readable form.

    :param name: Name object to return the DN from
    :param short: Use short form (default: False)
    :param delimiter: Delimiter string or character between two parts (default: ', ')

    :returns: the name string
    """
    if isinstance(name, Name):  # asn1crypto.x509.Name):
        name = name.native

    # For the shortform, we have a lookup table
    # See RFC4514 for more details
    _ = {
        'business_category': ("businessCategory", "businessCategory"),
        'serial_number': ("serialNumber", "serialNumber"),
        'country_name': ("C", "countryName"),
        'postal_code': ("postalCode", "postalCode"),
        'state_or_province_name': ("ST", "stateOrProvinceName"),
        'locality_name': ("L", "localityName"),
        'street_address': ("street", "streetAddress"),
        'organization_name': ("O", "organizationName"),
        'organizational_unit_name': ("OU", "organizationalUnitName"),
        'title': ("title", "title"),
        'common_name': ("CN", "commonName"),
        'initials': ("initials", "initials"),
        'generation_qualifier': ("generationQualifier", "generationQualifier"),
        'surname': ("SN", "surname"),
        'given_name': ("GN", "givenName"),
        'name': ("name", "name"),
        'pseudonym': ("pseudonym", "pseudonym"),
        'dn_qualifier': ("dnQualifier", "dnQualifier"),
        'telephone_number': ("telephoneNumber", "telephoneNumber"),
        'email_address': ("E", "emailAddress"),
        'domain_component': ("DC", "domainComponent"),
        'name_distinguisher': ("nameDistinguisher", "nameDistinguisher"),
        'organization_identifier': (
            "organizationIdentifier",
            "organizationIdentifier",
        ),
    }
    return delimiter.join(
        [
            "{}={}".format(
                _.get(attr, (attr, attr))[0 if short else 1], name[attr]
            )
            for attr in name
        ]
    )


def dump_additional_attributes(additional_attributes):
    """try to parse additional attributes, but ends up to hexdump if the scheme is unknown"""

    attributes_raw = io.BytesIO(additional_attributes)
    attributes_hex = binascii.hexlify(additional_attributes)

    if not len(additional_attributes):
        return attributes_hex

    (len_attribute,) = unpack('<I', attributes_raw.read(4))
    if len_attribute != 8:
        return attributes_hex

    (attr_id,) = unpack('<I', attributes_raw.read(4))
    if attr_id != APK_SIG_ATTR_V2_STRIPPING_PROTECTION:
        return attributes_hex

    (scheme_id,) = unpack('<I', attributes_raw.read(4))

    return "stripping protection set, scheme %d" % scheme_id

def comparison_name(
    name: x509.Name, *, android: bool = False
) -> list[list[tuple[str, str]]]:
    """
    ```
        * Method is dual-licensed under the Apache License 2.0 and GPLv3+.
        * The original author has granted permission to use this code snippet under the
        * Apache License 2.0 for inclusion in this project.
        * https://github.com/obfusk/x509_canonical_name.py/blob/master/x509_canonical_name.py
    ```

    Canonical representation of x509.Name as nested list.

    Returns a list of RDNs which are a list of AVAs which are a (type, value)
    tuple, where type is the standard name or dotted OID, and value is the
    normalised string representation of the value.
    """

    return [
        [(t, nv) for _, t, nv, _ in avas]
        for avas in x509_ordered_name(name, android=android)
    ]

def x509_ordered_name(
    name: x509.Name,
    *,  # type: ignore[no-any-unimported]
    android: bool = False,
) -> list[list[tuple[int, str, str, str]]]:
    """
    ```
        * Method is dual-licensed under the Apache License 2.0 and GPLv3+.
        * The original author has granted permission to use this code snippet under the
        * Apache License 2.0 for inclusion in this project.
        * https://github.com/obfusk/x509_canonical_name.py/blob/master/x509_canonical_name.py
    ```

    Representation of `x509.Name` as nested list, in canonical ordering (but also
    including non-canonical pre-normalised string values).

    Returns a list of RDNs which are a list of AVAs which are a (oid, type,
    normalised_value, esc_value) tuple, where oid is 0 for standard names and 1
    for dotted OIDs, type is the standard name or dotted OID, normalised_value
    is the normalised string representation of the value, and esc_value is the
    string value before normalisation (but after escaping).

    NB: control characters are not escaped, only characters in ",+<>;\"\\" and
    "#" at the start (before "whitespace" trimming) are.

    [X500Principal.getName](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/security/auth/x500/X500Principal.html#getName(java.lang.String))
    [AVA.java](https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/x509/AVA.java#L805)
    [RDN.java (472)](https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/x509/RDN.java#L472)
    [RDN.java (481)](https://android.googlesource.com/platform/libcore/+/refs/heads/android14-release/ojluni/src/main/java/sun/security/x509/RDN.java#481)
    """

    def key(
        ava: tuple[int, str, str, str]
    ) -> tuple[int, str| list[int], str]:
        o, t, nv, _ = ava
        if android and o:
            return o, [int(x) for x in t.split(".")], nv
        return o, t, nv

    DS, U8, PS = (
        x509.DirectoryString,
        x509.UTF8String,
        x509.PrintableString,
    )
    oids = {
        "2.5.4.3": ("common_name", "cn"),
        "2.5.4.6": ("country_name", "c"),
        "2.5.4.7": ("locality_name", "l"),
        "2.5.4.8": ("state_or_province_name", "st"),
        "2.5.4.9": ("street_address", "street"),
        "2.5.4.10": ("organization_name", "o"),
        "2.5.4.11": ("organizational_unit_name", "ou"),
        "0.9.2342.19200300.100.1.1": ("user_id", "uid"),
        "0.9.2342.19200300.100.1.25": ("domain_component", "dc"),
    }
    esc = {ord(c): f"\\{c}" for c in ",+<>;\"\\"}
    cws = "".join(
        chr(i) for i in range(32 + 1)
    )  # control (but not esc) and whitespace
    data = []
    for rdn in reversed(name.chosen):
        avas = []
        for ava in rdn:
            at, av = ava["type"], ava["value"]
            if at.dotted in oids:
                o, t = 0, oids[at.dotted][1]  # order standard before OID
            else:
                o, t = 1, at.dotted
            if o or not (
                isinstance(av, DS) and isinstance(av.chosen, (U8, PS))
            ):
                ev = nv = "#" + binascii.hexlify(av.dump()).decode()
            else:
                ev = (av.native or "").translate(esc)
                if ev.startswith("#"):
                    ev = "\\" + ev
                nv = unicodedata.normalize(
                    "NFKD",
                    re.sub(r" +", " ", ev).strip(cws).upper().lower(),
                )
            avas.append((o, t, nv, ev))
        data.append(sorted(avas, key=key))
    return data


def canonical_name(name: Name, android: bool = False) -> str:
    """
    ```
        * Method is dual-licensed under the Apache License 2.0 and GPLv3+.
        * The original author has granted permission to use this code snippet under the
        * Apache License 2.0 for inclusion in this project.
        * https://github.com/obfusk/x509_canonical_name.py/blob/master/x509_canonical_name.py
    ```

    Returns canonical representation of `asn1crypto.x509.Name` as str (with raw control characters
    in places those are not stripped by normalisation).
    """
    # return ",".join("+".join(f"{t}:{v}" for _, t, v in avas) for avas in self.comparison_name(name))
    return ",".join(
        "+".join(f"{t}={v}" for t, v in avas)
        for avas in comparison_name(name, android=android)
    )
