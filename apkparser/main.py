import argparse
import io

from .helper.logging import LOGGER
from . import APK, OPTION_AXML, OPTION_SIGNATURE, OPTION_PERMISSION


def initParser():
    parser = argparse.ArgumentParser(
        prog='apkparser',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='APK Parser',
    )

    parser.add_argument('-i', '--input', type=str, help='input APK file')

    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    args = parser.parse_args()
    return args


arguments = initParser()


def app():
    if arguments.input:
        with open(arguments.input, 'rb') as fd:
            a = APK(io.BytesIO(fd.read()), {OPTION_AXML: True, OPTION_SIGNATURE: True, OPTION_PERMISSION: True})
            LOGGER.info(a.get_files())
            LOGGER.info(a.get_android_manifest().package)
            LOGGER.info(a.get_android_manifest().permissions)
            LOGGER.info(a.get_android_manifest().uses_permissions)
            LOGGER.info(a.get_files_crc32())
            LOGGER.info(a.get_files_types())
            LOGGER.info(f"Application name = {a.get_app_name()}")
            LOGGER.info(f"Main Activity = {a.get_main_activity()}")
            LOGGER.info(f"Activities = {a.get_activities()}")
            for activity in a.get_activities():
                LOGGER.info(f"\tIntent filters = {a.get_intent_filters('activity', activity)}")
            LOGGER.info(f"Activities alias = {a.get_activity_aliases()}")

            LOGGER.info(f"Services = {a.get_services()}")
            for service in a.get_services():
                LOGGER.info(f"\tIntent filters = {a.get_intent_filters('service', service)}")

            LOGGER.info(f"Receivers = {a.get_receivers()}")
            for receiver in a.get_receivers():
                LOGGER.info(f"\tIntent filters = {a.get_intent_filters('receiver', receiver)}")

            LOGGER.info(f"Providers = {a.get_providers()}")

            LOGGER.info(f"Signature = {a.signature.get_signature()}")
            LOGGER.info(f"Signature names = {a.signature.get_signature_names()}")
            
            LOGGER.info(f"is signed = {a.signature.is_signed()}")
            
            LOGGER.info(f"v1 = {a.signature.is_signed_v1()}")
            LOGGER.info(f"v2 = {a.signature.is_signed_v2()}")
            LOGGER.info(f"v3 = {a.signature.is_signed_v3()}")
            LOGGER.info(a.signature.get_certificates())
            LOGGER.info(a.signature.get_public_keys_der_v3())
            LOGGER.info(a.signature.get_certificates_v2())

            LOGGER.info(f"Libraries = {a.get_libraries()}")
            LOGGER.info(f"Multidex = {a.is_multidex()}")

            LOGGER.info(f"get_uses_implied_permission_list = {a.permissions.get_uses_implied_permission_list()}")
            LOGGER.info(f"get_details_permissions = {a.permissions.get_details_permissions()}")
            LOGGER.info(f"get_requested_aosp_permissions = {a.permissions.get_requested_aosp_permissions()}")
            LOGGER.info(f"get_requested_aosp_permissions_details = {a.permissions.get_requested_aosp_permissions_details()}")
            LOGGER.info(f"get_declared_permissions = {a.permissions.get_declared_permissions()}")

    return 0


if __name__ == '__main__':
    app()
