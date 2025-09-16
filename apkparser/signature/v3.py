from . import APKV2SignedData, APKV2Signer

class APKV3SignedData(APKV2SignedData):
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : [apksigning v3](https://source.android.com/security/apksigning/v3.html)
    """

    def __init__(self) -> None:
        super().__init__()
        self.minSDK: int = -1
        self.maxSDK: int = -1

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7FFFFFFF:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join(
            [
                'signer minSDK : {:d}'.format(self.minSDK),
                'signer maxSDK : {:s}'.format(max_sdk_str),
                base_str,
            ]
        )


class APKV3Signer(APKV2Signer):
    """
    This class holds all data associated with an APK V3 SigningBlock signer.
    source : [apksigning v3](https://source.android.com/security/apksigning/v3.html)
    """

    def __init__(self) -> None:
        super().__init__()
        self.minSDK: int = -1
        self.maxSDK: int = -1

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7FFFFFFF:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join(
            [
                'signer minSDK : {:d}'.format(self.minSDK),
                'signer maxSDK : {:s}'.format(max_sdk_str),
                base_str,
            ]
        )
