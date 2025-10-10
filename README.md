<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">APK-PARSER</h2>

# APK Parser: Your Crowbar for Android Archive

<div align="center">

![Powered](https://img.shields.io/badge/androguard-green?style=for-the-badge&label=Powered%20by&link=https%3A%2F%2Fgithub.com%2Fandroguard)
![Sponsor](https://img.shields.io/badge/sponsor-nlnet-blue?style=for-the-badge&link=https%3A%2F%2Fnlnet.nl%2F)
![PYPY](https://img.shields.io/badge/PYPI-APKPARSER-violet?style=for-the-badge&link=https%3A%2F%2Fpypi.org%2Fproject%2Fapkparser-ag%2F)

</div>

## Description

At its core, every APK is a fortress built on a simple foundation: the ZIP archive. apk-parser is the key to that fortress.

This is a standalone, dependency-free, native Python library designed to do one thing and do it exceptionally well: deconstruct the fundamental structure of an Android Application Package (APK). It is a foundational pillar of the new Androguard Ecosystem, providing robust, reliable, and performant access to the raw contents of any APK file.

### Philosophy

Following the "Deconstruct to Reconstruct" philosophy of the new Androguard, apk-parser has been uncoupled from the main analysis engine. It exists as an independent, lightweight, and highly portable tool. By focusing solely on the archive layer, it provides a stable and predictable interface for any tool that needs to peer inside an APK.

### Key Features

- Archive Integrity & Parsing: Reads the full structure of the APK's ZIP archive, including the central directory, without relying on external unzip commands.

- File Extraction: Pull any file from the archive by its path, from classes.dex to raw resources in the res/ directory.

- Manifest Access: Seamlessly locate and extract the binary AndroidManifest.xml file, ready to be passed to the axml library for decoding.

- Signature & Metadata: Parses the META-INF directory to extract signature block files and certificate information, allowing for basic signature verification.

- Pure & Pythonic: Written in native Python with zero external dependencies for maximum portability and a minimal footprint.

## Installation


If you would like to install it locally, please create a new venv to use it directly, and then:

```
$ git clone https://github.com/androguard/apk-parser.git
$ pip install -e .
```

or directly via pypi:
```
$ pip install apkparser-ag
```

## Usage

```apkparser-ag``` is also a quick command line to extract information about an APK:

```
(.venv) ➜  apk-parser git:(main) ✗ apkparser -i Android.apk
```


## API

Let's say you have access to a python shell and import apkparser, you can load it with full analysis like:
```
import apkparser

w = apkparser.APK(io.BytesIO(open("Android.apk", "rb").read()), {apkparser.OPTION_AXML: True, apkparser.OPTION_SIGNATURE: True, apkparser.OPTION_PERMISSION: True})
```

For each class you can get documentation via:
```
help(w)
```

### Basic information

```
>>> w.get_main_activity()
'me.proton.android.calendar.presentation.main.MainActivity'
```

```
>>> [i for i in w.get_dex_names()]
['classes.dex', 'classes10.dex', 'classes11.dex', 'classes12.dex', 'classes13.dex', 'classes14.dex', 'classes15.dex', 'classes2.dex', 'classes3.dex', 'classes4.dex', 'classes5.dex', 'classes6.dex', 'classes7.dex', 'classes8.dex', 'classes9.dex']
```

```
>>> w.get_services()
['androidx.room.MultiInstanceInvalidationService', 'com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService', 'androidx.work.impl.background.systemjob.SystemJobService', 'com.google.android.datatransport.runtime.backends.TransportBackendDiscovery', 'com.google.android.gms.auth.api.signin.RevocationBoundService', 'androidx.work.impl.background.systemalarm.SystemAlarmService', 'androidx.work.impl.foreground.SystemForegroundService', 'me.proton.android.calendar.CalendarWidgetRemoteViewsService']
```

```
>>> w.get_android_manifest()
<axml.axml.printer.AXMLPrinter object at 0x79cffeb44ad0>
```

```
>>> w.get_app_name()
'Proton Calendar'
```

### File Extraction

```
>>> w.get_files()
['META-INF/com/android/build/gradle/app-metadata.properties', 'META-INF/version-control-info.textproto', 'assets/dexopt/baseline.prof', 'assets/dexopt/baseline.profm', 'classes.dex', 'classes10.dex', 'classes11.dex', 'classes12.dex', 'classes13.dex', 'classes14.dex', 'classes15.dex', 'classes2.dex', 'classes3.dex', 'classes4.dex', 'classes5.dex', 'classes6.dex', 'classes7.dex', 'classes8.dex', 'classes9.dex', 'lib/arm64-v8a/libandroidx.graphics.path.so', 'lib/arm64-v8a/libgojni.so', 'lib/arm64-v8a/libsentry-android.so', 'lib/arm64-v8a/libsentry.so', ....]
```

### Signature

The ```signature``` object in the APK class can handle all things related to signatures, certificates related to the APK, like:

```
>>> w.signature.get_certificates()
[<asn1crypto.x509.Certificate 133934071544272 b'0\x82\x03\xc50\x82\x02\xad\xa0\x03\x02\x01\x02\x02\x04\x07\xf5\x0280\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000\x81\x921\x0b0\t\x06\x03U\x04\x06\x13\x02CH1\x0f0\r\x06\x03U\x04\x08\x13\x06Geneva1\x0f0\r\x06\x03U\x04\x07\x13\x06Geneva1\x1f0\x1d\x06\x03U\x04\n\x13\x16Proton Technologies AG1\x1f0\x1d\x06\x03U\x04\x0b\x13\x16Proton Technologies...]
```


```
signature.find_certificate(
signature.get_certificates_v1()
signature.get_public_keys_v2()
signature.is_signed()
signature.parse_v3_signing_block()
signature.get_certificate(
signature.get_certificates_v2()
signature.get_public_keys_v3()
signature.is_signed_v1()
signature.verify_signature(
signature.get_certificate_der(
signature.get_certificates_v3()
signature.get_signature()
signature.is_signed_v2()
signature.verify_signer_info_against_sig_file(
signature.get_certificates()
signature.get_hash_algorithm(
signature.get_signature_name()
signature.is_signed_v3()                        
signature.get_certificates_der_v2()
signature.get_public_keys_der_v2()
signature.get_signature_names()
signature.parse_v2_signing_block()              
signature.get_certificates_der_v3()
signature.get_public_keys_der_v3()
signature.get_signatures()
signature.parse_v2_v3_signature()               
```

### Permissions

The ```permissions``` object in the APK can handle all things related to permissions usage, detailed permissions, aosp permissions etc, like:

```
>>> w.permissions.get_details_permissions()
{'android.permission.USE_EXACT_ALARM': ['normal', 'Schedule alarms or event reminders', 'This app can schedule actions like alarms and reminders to notify you at a desired time in the future.'], 'android.permission.FOREGROUND_SERVICE': ['normal|instant', 'run foreground service', 'Allows the app to make use of foreground services.'], ...}
```

## License

Distributed under the [Apache License, Version 2.0](LICENSE).