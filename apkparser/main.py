import argparse
import sys
import io

from .helper.logging import LOGGER
from . import APK

def initParser():
    parser = argparse.ArgumentParser(
        prog='apkparser',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='APK Parser')

    parser.add_argument('-i', '--input', type=str,
                        help='input APK file')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    args = parser.parse_args()
    return args


arguments = initParser()

def app():
    if arguments.input:
        with open(arguments.input, 'rb') as fd:
            a = APK(io.BytesIO(fd.read()))
            print(a.get_files())
    return 0

if __name__ == '__main__':
    app()
