# -*- coding: utf-8 -*-
import io
import mmap
import os
import tempfile
import unittest

from apkparser.zip.headers import EndOfCentralDirectoryRecord

test_dir = os.path.dirname(os.path.abspath(__file__))
HELLO_APK = os.path.join(test_dir, 'data/APK/hello-world.apk')


class EndOfCentralDirectoryRecordMmapTest(unittest.TestCase):
    """APK(Path) memory maps the file, and mmap.seek() returns None where file
    objects and BytesIO return the new offset. The EOCD scan used the return
    value as the file size, so any non-ZIP file reached through a path raised
    TypeError instead of the usual ValueError."""

    def test_non_zip_file_through_mmap_raises_value_error(self):
        payload = b'this is not a zip file, there is no central directory'

        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp:
            tmp.write(payload * (2000 // len(payload)))
            path = tmp.name
        try:
            with open(path, 'rb') as apk_b:
                mapped = mmap.mmap(apk_b.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    with self.assertRaises(ValueError) as ctx:
                        EndOfCentralDirectoryRecord.parse(mapped)
                finally:
                    mapped.close()
        finally:
            os.unlink(path)

        self.assertIn('EOCD', str(ctx.exception))

    def test_mmap_and_bytesio_agree(self):
        with open(HELLO_APK, 'rb') as apk_b:
            raw = apk_b.read()

        from_bytes = EndOfCentralDirectoryRecord.parse(io.BytesIO(raw))

        with open(HELLO_APK, 'rb') as apk_b:
            mapped = mmap.mmap(apk_b.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                from_mmap = EndOfCentralDirectoryRecord.parse(mapped)
            finally:
                mapped.close()

        self.assertEqual(from_bytes.signature, from_mmap.signature)
        self.assertEqual(
            from_bytes.total_number_of_central_directory_records,
            from_mmap.total_number_of_central_directory_records,
        )
        self.assertEqual(
            from_bytes.offset_of_start_of_central_directory,
            from_mmap.offset_of_start_of_central_directory,
        )


if __name__ == '__main__':
    unittest.main()
