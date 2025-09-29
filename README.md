<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">APK-PARSER</h2>

# APK Parser: Your Crowbar for Android Archive

<div align="center">

![Powered](https://img.shields.io/badge/androguard-green?style=for-the-badge&label=Powered%20by&link=https%3A%2F%2Fgithub.com%2Fandroguard)
![Sponsor](https://img.shields.io/badge/sponsor-nlnet-blue?style=for-the-badge&link=https%3A%2F%2Fnlnet.nl%2F)
![PYPY](https://img.shields.io/badge/PYPI-APKPARSER-violet?style=for-the-badge&link=https%3A%2F%2Fpypi.org%2Fproject%2Faxml%2F)

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

## API

## License

Distributed under the [Apache License, Version 2.0](LICENSE).