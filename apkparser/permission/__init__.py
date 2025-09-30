from apkparser.helper.logging import LOGGER

# Dictionary of the different protection levels mapped to their corresponding attribute names as described in
# https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/content/pm/PermissionInfo.java
protection_flags_to_attributes = {
    "0x00000000": "normal",
    "0x00000001": "dangerous",
    "0x00000002": "signature",
    "0x00000003": "signature or system",
    "0x00000004": "internal",
    "0x00000010": "privileged",
    "0x00000020": "development",
    "0x00000040": "appop",
    "0x00000080": "pre23",
    "0x00000100": "installer",
    "0x00000200": "verifier",
    "0x00000400": "preinstalled",
    "0x00000800": "setup",
    "0x00001000": "instant",
    "0x00002000": "runtime only",
    "0x00004000": "oem",
    "0x00008000": "vendor privileged",
    "0x00010000": "system text classifier",
    "0x00020000": "wellbeing",
    "0x00040000": "documenter",
    "0x00080000": "configurator",
    "0x00100000": "incident report approver",
    "0x00200000": "app predictor",
    "0x00400000": "module",
    "0x00800000": "companion",
    "0x01000000": "retail demo",
    "0x02000000": "recents",
    "0x04000000": "role",
    "0x08000000": "known signer",
}  

class Permission(object):
    def get_uses_implied_permission_list(self) -> list[str]:
        """
        Return all permissions implied by the target SDK or other permissions.
        
        :returns: list of all permissions implied by the target SDK or other permissions as strings
        """
        target_sdk_version = self.get_effective_target_sdk_version()

        READ_CALL_LOG = 'android.permission.READ_CALL_LOG'
        READ_CONTACTS = 'android.permission.READ_CONTACTS'
        READ_EXTERNAL_STORAGE = 'android.permission.READ_EXTERNAL_STORAGE'
        READ_PHONE_STATE = 'android.permission.READ_PHONE_STATE'
        WRITE_CALL_LOG = 'android.permission.WRITE_CALL_LOG'
        WRITE_CONTACTS = 'android.permission.WRITE_CONTACTS'
        WRITE_EXTERNAL_STORAGE = 'android.permission.WRITE_EXTERNAL_STORAGE'

        implied = []

        implied_WRITE_EXTERNAL_STORAGE = False
        if target_sdk_version < 4:
            if WRITE_EXTERNAL_STORAGE not in self.permissions:
                implied.append([WRITE_EXTERNAL_STORAGE, None])
                implied_WRITE_EXTERNAL_STORAGE = True
            if READ_PHONE_STATE not in self.permissions:
                implied.append([READ_PHONE_STATE, None])

        if (
            WRITE_EXTERNAL_STORAGE in self.permissions
            or implied_WRITE_EXTERNAL_STORAGE
        ) and READ_EXTERNAL_STORAGE not in self.permissions:
            maxSdkVersion = None
            for name, version in self.uses_permissions:
                if name == WRITE_EXTERNAL_STORAGE:
                    maxSdkVersion = version
                    break
            implied.append([READ_EXTERNAL_STORAGE, maxSdkVersion])

        if target_sdk_version < 16:
            if (
                READ_CONTACTS in self.permissions
                and READ_CALL_LOG not in self.permissions
            ):
                implied.append([READ_CALL_LOG, None])
            if (
                WRITE_CONTACTS in self.permissions
                and WRITE_CALL_LOG not in self.permissions
            ):
                implied.append([WRITE_CALL_LOG, None])

        return implied

    def _update_permission_protection_level(
        self, protection_level, sdk_version
    ):
        if not sdk_version or int(sdk_version) <= 15:
            return protection_level.replace('Or', '|').lower()
        return protection_level

    def _fill_deprecated_permissions(self, permissions):
        min_sdk = self.get_min_sdk_version()
        target_sdk = self.get_target_sdk_version()
        filled_permissions = permissions.copy()
        for permission in filled_permissions:
            protection_level, label, description = filled_permissions[
                permission
            ]
            if (
                not label or not description
            ) and permission in self.permission_module_min_sdk:
                x = self.permission_module_min_sdk[permission]
                protection_level = self._update_permission_protection_level(
                    x['protectionLevel'], min_sdk
                )
                filled_permissions[permission] = [
                    protection_level,
                    x['label'],
                    x['description'],
                ]
            else:
                filled_permissions[permission] = [
                    self._update_permission_protection_level(
                        protection_level, target_sdk
                    ),
                    label,
                    description,
                ]
        return filled_permissions

    def get_details_permissions(self) -> dict[str, list[str]]:
        """
        Return permissions with details.

        This can only return details about the permission, if the permission is
        defined in the AOSP.

        :returns: permissions with details: dict of `{permission: [protectionLevel, label, description]}`
        """
        l = {}

        for i in self.permissions:
            if i in self.permission_module:
                x = self.permission_module[i]
                l[i] = [x["protectionLevel"], x["label"], x["description"]]
            elif i in self.declared_permissions:
                protectionLevel_hex = self.declared_permissions[i]["protectionLevel"]
                try:
                    key = int(protectionLevel_hex, 0) if isinstance(protectionLevel_hex, str) else protectionLevel_hex
                except Exception:
                    key = None

                protectionLevel = protection_flags_to_attributes.get(key) if isinstance(key, int) else None
                if protectionLevel is None:
                    protectionLevel = protection_flags_to_attributes.get(protectionLevel_hex)
                if protectionLevel is None and isinstance(key, int):
                    protectionLevel = protection_flags_to_attributes.get(key & 0xF)
                if protectionLevel is None:
                    protectionLevel = f"unknown({protectionLevel_hex!r})"

                l[i] = [
                    protectionLevel,
                    "Unknown permission from android reference",
                    "Unknown permission from android reference",
                ]
            else:
                # Is there a valid case not belonging to the above two?
                LOGGER.info(f"Unknown permission {i}")
        return self._fill_deprecated_permissions(l)

    def get_requested_aosp_permissions(self) -> list[str]:
        """
        Returns requested permissions declared within AOSP project.

        This includes several other permissions as well, which are in the platform apps.

        :returns: requested permissions
        """
        aosp_permissions = []
        all_permissions = self.get_permissions()
        for perm in all_permissions:
            if perm in list(self.permission_module.keys()):
                aosp_permissions.append(perm)
        return aosp_permissions

    def get_requested_aosp_permissions_details(self) -> dict[str, list[str]]:
        """
        Returns requested aosp permissions with details.

        :returns: requested aosp permissions
        """
        l = {}
        for i in self.permissions:
            try:
                l[i] = self.permission_module[i]
            except KeyError:
                # if we have not found permission do nothing
                continue
        return l

    def get_requested_third_party_permissions(self) -> list[str]:
        """
        Returns list of requested permissions not declared within AOSP project.

        :returns: requested permissions
        """
        third_party_permissions = []
        all_permissions = self.get_permissions()
        for perm in all_permissions:
            if perm not in list(self.permission_module.keys()):
                third_party_permissions.append(perm)
        return third_party_permissions

    def get_declared_permissions(self) -> list[str]:
        """
        Returns list of the declared permissions.

        :returns: list of declared permissions
        """
        return list(self.declared_permissions.keys())

    def get_declared_permissions_details(self) -> dict[str, list[str]]:
        """
        Returns declared permissions with the details.

        :returns: declared permissions
        """
        return self.declared_permissions