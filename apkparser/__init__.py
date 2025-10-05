import io
import re
import hashlib
from typing import Iterator
from xmlrpc.client import boolean
from zlib import crc32
import magic

from apkparser.helper.logging import LOGGER
from apkparser.zip import headers
from apkparser.signature import APKSignature
from apkparser.utils import is_android_raw
from apkparser.permissions import Permissions

from axml.axml import AXMLPrinter, namespace
from axml.arsc import ARSCParser, ARSCResTableConfig

APK_FILENAME_MANIFEST = "AndroidManifest.xml"

class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class FileNotPresent(Error):
    pass


OPTION_AXML = "AXML"
OPTION_SIGNATURE = "SIGNATURE"
OPTION_PERMISSION = "PERMISSION"


class APK(object):
    def __init__(
        self,
        raw: io.BytesIO,
        options: dict[str, bool] = {},
    ):
        self._raw = raw

        self.valid_apk: boolean = False
        self.axml: AXMLPrinter|None = None
        self.signature: APKSignature|None = None
        self.permissions: Permissions|None = None

        self.arsc = {}  

        self._files = {}
        self.files_crc32 = {}

        self._sha256 = hashlib.sha256(raw.read()).hexdigest()
        # Set the filename to something sane
        self.filename = "raw_apk_sha256:{}".format(self._sha256)

        self._raw.seek(0)
        self.zip: headers.ZipEntry = headers.ZipEntry.parse(self._raw, True)

        # Parsing non mandatory structures
        self._parse_fields(options)

    def _parse_fields(self, options: dict[str, bool]):
        self.declared_permissions = {}

        if options.get(OPTION_AXML):
            axml_bytes = self.zip.read(APK_FILENAME_MANIFEST)
            if axml_bytes:
                self.axml = AXMLPrinter(axml_bytes)
            else:
                LOGGER.warning("seems the APK has no AndroidManifest.xml")

        if options.get(OPTION_SIGNATURE):
            self.signature = APKSignature(self._raw, self.zip, self.axml)


        if self.axml:
            if options.get(OPTION_PERMISSION):
                self.permissions = Permissions(self)


    def _get_res_string_value(self, string):
        if not string.startswith('@string/'):
            return string
        string_key = string[9:]

        res_parser = self.get_android_resources()
        if not res_parser:
            return ''
        string_value = ''
        for package_name in res_parser.get_packages_names():
            extracted_values = res_parser.get_string(package_name, string_key)
            if extracted_values:
                string_value = extracted_values[1]
                break
        return string_value
    
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

    def _get_file_magic_name(self, buffer: bytes) -> str:
        """
        Return the filetype guessed for a buffer
        :param buffer: bytes

        :returns: guessed filetype, or "Unknown" if not resolved
        """
        try:
            # 1024 byte are usually enough to test the magic
            ftype = magic.from_buffer(buffer[:1024])
        except magic.MagicException as e:
            LOGGER.exception("Error getting the magic type: %s", e)
            return default

        if not ftype:
            return default
        else:
            return self._patch_magic(buffer, ftype)

    def _patch_magic(self, buffer, orig):
        """
        Overwrite some probably wrong detections by mime libraries

        :param buffer: bytes of the file to detect
        :param orig: guess by mime libary
        :returns: corrected guess
        """
        if (
            ("Zip" in orig)
            or ('(JAR)' in orig)
            and is_android_raw(buffer) == 'APK'
        ):
            return "Android application package file"

        return orig
    
    def get_files_types(self) -> dict[str, str]:
        """
        Return the files inside the APK with their associated types (by using [python-magic](https://pypi.org/project/python-magic/))

        At the same time, the CRC32 are calculated for the files.

        :returns: the files inside the APK with their associated types
        """
        if self._files == {}:
            # Generate File Types / CRC List
            for i in self.get_files():
                buffer = self._get_crc32(i)
                self._files[i] = self._get_file_magic_name(buffer)

        return self._files


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

    def _get_crc32(self, filename: str):
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
                LOGGER.error(
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

    def get_android_manifest(self) -> AXMLPrinter | None:
        """
        Return the parsed xml object which corresponds to the `AndroidManifest.xml` file

        :returns: the parsed xml object
        """
        return self.axml

    def get_android_resources(self) -> ARSCParser|None:
        """
        Return the [ARSCParser][androguard.core.axml.ARSCParser] object which corresponds to the `resources.arsc` file

        :returns: the `ARSCParser` object
        """
        try:
            return self.arsc["resources.arsc"]
        except KeyError:
            if "resources.arsc" not in self.zip.namelist():
                # There is a rare case, that no resource file is supplied.
                # Maybe it was added manually, thus we check here
                return None
            self.arsc["resources.arsc"] = ARSCParser(
                self.zip.read("resources.arsc")
            )
            return self.arsc["resources.arsc"]
        
    def get_app_name(self, locale=None) -> str:
        """
        Return the appname of the APK
        This name is read from the `AndroidManifest.xml`
        using the application `android:label`.
        If no label exists, the `android:label` of the main activity is used.

        If there is also no main activity label, an empty string is returned.

        :returns: the appname of the APK
        """

        app_name = self.axml.get_attribute_value('application', 'label')
        if app_name is None:
            activities = self.get_main_activities()
            main_activity_name = None
            if len(activities) > 0:
                main_activity_name = activities.pop()

            # FIXME: would need to use _format_value inside get_attribute_value for each returned name!
            # For example, as the activity name might be foobar.foo.bar but inside the activity it is only .bar
            app_name = self.get_attribute_value(
                'activity', 'label', name=main_activity_name
            )

        if app_name is None:
            # No App name set
            # TODO return packagename instead?
            LOGGER.warning(
                "It looks like that no app name is set for the main activity!"
            )
            return ""

        if app_name.startswith("@"):
            res_parser = self.get_android_resources()
            if not res_parser:
                # TODO: What should be the correct return value here?
                return app_name

            res_id, package = res_parser.parse_id(app_name)

            # If the package name is the same as the APK package,
            # we should be able to resolve the ID.
            if package and package != self.axml.package:
                if package == 'android':
                    # TODO: we can not resolve this, as we lack framework-res.apk
                    # one exception would be when parsing framework-res.apk directly.
                    LOGGER.warning(
                        "Resource ID with android package name encountered! "
                        "Will not resolve, framework-res.apk would be required."
                    )
                    return app_name
                else:
                    # TODO should look this up, might be in the resources
                    LOGGER.warning(
                        "Resource ID with Package name '{}' encountered! Will not resolve".format(
                            package
                        )
                    )
                    return app_name

            try:
                config = (
                    ARSCResTableConfig(None, locale=locale)
                    if locale
                    else ARSCResTableConfig.default_config()
                )
                app_name = res_parser.get_resolved_res_configs(res_id, config)[
                    0
                ][1]
            except Exception as e:
                LOGGER.warning("Exception selecting app name: %s" % e)
        return app_name

    def get_app_icon(self, max_dpi: int = 65536) -> str|None:
        """
        Return the first icon file name, which density is not greater than max_dpi,
        unless exact icon resolution is set in the manifest, in which case
        return the exact file.

        This information is read from the `AndroidManifest.xml`

        From <https://developer.android.com/guide/practices/screens_support.html>
        and <https://developer.android.com/ndk/reference/group___configuration.html>

        * DEFAULT                             0dpi
        * ldpi (low)                        120dpi
        * mdpi (medium)                     160dpi
        * TV                                213dpi
        * hdpi (high)                       240dpi
        * xhdpi (extra-high)                320dpi
        * xxhdpi (extra-extra-high)         480dpi
        * xxxhdpi (extra-extra-extra-high)  640dpi
        * anydpi                          65534dpi (0xFFFE)
        * nodpi                           65535dpi (0xFFFF)

        There is a difference between nodpi and anydpi:
        nodpi will be used if no other density is specified. Or the density does not match.
        nodpi is the fallback for everything else. If there is a resource that matches the DPI,
        this is used.
        anydpi is also valid for all densities but in this case, anydpi will overrule all other files!
        Therefore anydpi is usually used with vector graphics and with constraints on the API level.
        For example adaptive icons are usually marked as anydpi.

        When it comes now to selecting an icon, there is the following flow:

        1. is there an anydpi icon?
        2. is there an icon for the dpi of the device?
        3. is there a nodpi icon?
        4. (only on very old devices) is there a icon with dpi 0 (the default)

        For more information read here: <https://stackoverflow.com/a/34370735/446140>

        :returns: the first icon file name, or None if no resources or app icon exists.
        """
        main_activity_name = self.get_main_activity()

        app_icon = self.axml.get_attribute_value(
            'activity', 'icon', name=main_activity_name
        )

        if not app_icon:
            app_icon = self.axml.get_attribute_value('application', 'icon')

        res_parser = self.get_android_resources()
        if not res_parser:
            # Can not do anything below this point to resolve...
            return None

        if not app_icon:
            res_id = res_parser.get_res_id_by_key(
                self.package, 'mipmap', 'ic_launcher'
            )
            if res_id:
                app_icon = "@%x" % res_id

        if not app_icon:
            res_id = res_parser.get_res_id_by_key(
                self.package, 'drawable', 'ic_launcher'
            )
            if res_id:
                app_icon = "@%x" % res_id

        if not app_icon:
            # If the icon can not be found, return now
            return None

        if app_icon.startswith("@"):
            app_icon_id = app_icon[1:]
            app_icon_id = app_icon_id.split(':')[-1]
            res_id = int(app_icon_id, 16)
            candidates = res_parser.get_resolved_res_configs(res_id)

            app_icon = None
            current_dpi = -1

            try:
                for config, file_name in candidates:
                    dpi = config.get_density()
                    if current_dpi < dpi <= max_dpi:
                        app_icon = file_name
                        current_dpi = dpi
            except Exception as e:
                logger.warning("Exception selecting app icon: %s" % e)

        return app_icon

    def get_main_activities(self) -> set[str]:
        """
        Return names of the main activities

        These values are read from the `AndroidManifest.xml`

        :returns: names of the main activities
        """
        x = set()
        y = set()

        decoded_axml = self.axml.get_xml_obj()

        activities_and_aliases = decoded_axml.findall(
            ".//activity"
        ) + decoded_axml.findall(".//activity-alias")

        for item in activities_and_aliases:
            # Some applications have more than one MAIN activity.
            # For example: paid and free content
            activityEnabled = item.get(namespace("enabled"))
            if activityEnabled == "false":
                continue

            for sitem in item.findall(".//action"):
                val = sitem.get(namespace("name"))
                if val == "android.intent.action.MAIN":
                    activity = item.get(namespace("name")) or item.get("name")
                    if activity is not None:
                        x.add(activity)
                    else:
                        LOGGER.warning('Main activity without name')

            for sitem in item.findall(".//category"):
                val = sitem.get(namespace("name"))
                if val == "android.intent.category.LAUNCHER":
                    activity = item.get(namespace("name")) or item.get("name")
                    if activity is not None:
                        y.add(activity)
                    else:
                        LOGGER.warning('Launcher activity without name')

        return x.intersection(y)

    def get_main_activity(self) -> str|None:
        """
        Return the name of the main activity

        This value is read from the `AndroidManifest.xml`

        :returns: the name of the main activity
        """
        activities = self.get_main_activities()
        if len(activities) == 1:
            return self.axml.format_value(activities.pop())
        elif len(activities) > 1:
            main_activities = {self.axml.format_value(ma) for ma in activities}
            # sorted is necessary
            # 9fc7d3e8225f6b377f9181a92c551814317b77e1aa0df4c6d508d24b18f0f633
            good_main_activities = sorted(
                main_activities.intersection(self.get_activities())
            )
            if good_main_activities:
                return good_main_activities[0]
            return sorted(main_activities)[0]
        return None


    def get_activities(self) -> list[str]:
        """
        Return the `android:name` attribute of all activities

        :returns: the list of `android:name` attribute of all activities
        """
        return list(self.axml.get_all_attribute_value("activity", "name"))

    def get_activity_aliases(self) -> list[dict[str, str]]:
        """
        Return the `android:name` and `android:targetActivity` attribute of all activity aliases.

        :returns: the list of `android:name` and `android:targetActivity` attribute of all activitiy aliases
        """
        ali = []
        for alias in self.axml.find_tags('activity-alias'):
            activity_alias = {}
            for attribute in ['name', 'targetActivity']:
                value = alias.get(attribute) or alias.get(namespace(attribute))
                if not value:
                    continue
                activity_alias[attribute] = self.axml.format_value(value)
            if activity_alias:
                ali.append(activity_alias)
        return ali
    
    def get_services(self) -> list[str]:
        """
        Return the `android:name` attribute of all services

        :returns: the list of the `android:name` attribute of all services
        """
        return list(self.axml.get_all_attribute_value("service", "name"))

    def get_receivers(self) -> list[str]:
        """
        Return the `android:name` attribute of all receivers

        :returns: the list of the `android:name` attribute of all receivers
        """
        return list(self.axml.get_all_attribute_value("receiver", "name"))

    def get_providers(self) -> list[str]:
        """
        Return the `android:name` attribute of all providers

        :returns: the list of the `android:name` attribute of all providers
        """
        return list(self.axml.get_all_attribute_value("provider", "name"))


    def get_intent_filters(
        self, itemtype: str, name: str
    ) -> dict[str, list[str]]:
        """
        Find intent filters for a given item and name.

        Intent filter are attached to activities, services or receivers.
        You can search for the intent filters of such items and get a dictionary of all
        attached actions and intent categories.

        :param itemtype: the type of parent item to look for, e.g. `activity`,  `service` or `receiver`
        :param name: the `android:name` of the parent item, e.g. activity name
        :returns: a dictionary with the keys `action` and `category` containing the `android:name` of those items
        """
        attributes = {
            "action": ["name"],
            "category": ["name"],
            "data": [
                'scheme',
                'host',
                'port',
                'path',
                'pathPattern',
                'pathPrefix',
                'mimeType',
            ],
        }

        d = {}
        for element in attributes.keys():
            d[element] = []

        for item in self.axml.get_xml_obj().findall(".//" + itemtype):
            if self.axml.format_value(item.get(namespace("name"))) == name:
                for sitem in item.findall(".//intent-filter"):
                    for element in d.keys():
                        for ssitem in sitem.findall(element):
                            if element == 'data':  # multiple attributes
                                values = {}
                                for attribute in attributes[element]:
                                    value = ssitem.get(namespace(attribute))
                                    if value:
                                        if value.startswith('@'):
                                            value = self.get_android_resources().get_res_value(
                                                value
                                            )
                                        values[attribute] = value

                                if values:
                                    d[element].append(values)
                            else:
                                for attribute in attributes[element]:
                                    value = ssitem.get(namespace(attribute))
                                    if value.startswith('@'):
                                        value = self.get_android_resources().get_res_value(value)

                                    if value not in d[element]:
                                        d[element].append(value)

        for element in list(d.keys()):
            if not d[element]:
                del d[element]

        return d
    
    def get_libraries(self) -> list[str]:
        """
        Return the `android:name` attributes for libraries

        :returns: the `android:name` attributes
        """
        return list(self.axml.get_all_attribute_value("uses-library", "name"))

    def get_features(self) -> list[str]:
        """
        Return a list of all `android:names` found for the tag `uses-feature`
        in the `AndroidManifest.xml`

        :returns: the `android:names` found
        """
        return list(self.axml.get_all_attribute_value("uses-feature", "name"))

    def is_wearable(self) -> bool:
        """
        Checks if this application is build for wearables by
        checking if it uses the feature 'android.hardware.type.watch'
        See: https://developer.android.com/training/wearables/apps/creating.html for more information.

        Not every app is setting this feature (not even the example Google provides),
        so it might be wise to not 100% rely on this feature.

        :returns: `True` if wearable, `False` otherwise
        """
        return 'android.hardware.type.watch' in self.get_features()

    def is_leanback(self) -> bool:
        """
        Checks if this application is build for TV (Leanback support)
        by checkin if it uses the feature 'android.software.leanback'

        :returns: `True` if leanback feature is used, `False` otherwise
        """
        return 'android.software.leanback' in self.get_features()

    def is_androidtv(self) -> bool:
        """
        Checks if this application does not require a touchscreen,
        as this is the rule to get into the TV section of the Play Store
        See: https://developer.android.com/training/tv/start/start.html for more information.

        :returns: `True` if 'android.hardware.touchscreen' is not required, `False` otherwise
        """
        return (
            self.axml.get_attribute_value(
                'uses-feature',
                'name',
                required="false",
                name="android.hardware.touchscreen",
            )
            == "android.hardware.touchscreen"
        )