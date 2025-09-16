from asn1crypto import x509
import binascii

def dump_digests_or_signatures(digests_or_sigs):

    infos = ""
    for i, dos in enumerate(digests_or_sigs):

        infos += "\n"
        infos += " [%d]\n" % i
        infos += "  - Signature Id : %s\n" % APK_SIG_ALGO_IDS.get(
            dos[0], hex(dos[0])
        )
        infos += "  - Digest: %s" % binascii.hexlify(dos[1])

    return infos


class APKV2SignedData:
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : [apksigning v2](https://source.android.com/security/apksigning/v2.html)
    """

    def __init__(self) -> None:
        self._bytes = None
        self.digests = None
        self.certificates = None
        self.additional_attributes = None

    def __str__(self):

        certs_infos = ""

        for i, cert in enumerate(self.certificates):
            x509_cert = x509.Certificate.load(cert)

            certs_infos += "\n"
            certs_infos += " [%d]\n" % i
            certs_infos += "  - Issuer: %s\n" % get_certificate_name_string(
                x509_cert.issuer, short=True
            )
            certs_infos += "  - Subject: %s\n" % get_certificate_name_string(
                x509_cert.subject, short=True
            )
            certs_infos += "  - Serial Number: %s\n" % hex(
                x509_cert.serial_number
            )
            certs_infos += "  - Hash Algorithm: %s\n" % x509_cert.hash_algo
            certs_infos += (
                "  - Signature Algorithm: %s\n" % x509_cert.signature_algo
            )
            certs_infos += (
                "  - Valid not before: %s\n"
                % x509_cert['tbs_certificate']['validity']['not_before'].native
            )
            certs_infos += (
                "  - Valid not after: %s"
                % x509_cert['tbs_certificate']['validity']['not_after'].native
            )

        return "\n".join(
            [
                'additional_attributes : {}'.format(
                    _dump_additional_attributes(self.additional_attributes)
                ),
                'digests : {}'.format(
                    _dump_digests_or_signatures(self.digests)
                ),
                'certificates : {}'.format(certs_infos),
            ]
        )


class APKV2Signer:
    """
    This class holds all data associated with an APK V2 SigningBlock signer.
    source : [apksigning v2](https://source.android.com/security/apksigning/v2.html)
    """

    def __init__(self) -> None:
        self._bytes = None
        self.signed_data = None
        self.signatures = None
        self.public_key = None

    def __str__(self):
        return "\n".join(
            [
                '{:s}'.format(str(self.signed_data)),
                'signatures : {}'.format(
                    _dump_digests_or_signatures(self.signatures)
                ),
                'public key : {}'.format(binascii.hexlify(self.public_key)),
            ]
        )
