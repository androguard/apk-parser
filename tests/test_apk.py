# -*- coding: utf-8 -*-
import io
import os
import unittest


from apkparser import APK, OPTION_AXML, OPTION_SIGNATURE

test_dir = os.path.dirname(os.path.abspath(__file__))

class APKTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(
            os.path.join(test_dir, 'data/APK/hello-world.apk'),
            "rb",
        ) as apk_b:
            cls.apk = APK(io.BytesIO(apk_b.read()), {OPTION_AXML: True, OPTION_SIGNATURE: True})

    def testAPK(self):
        self.assertTrue(self.apk)
        self.assertIsNotNone(self.apk.axml)
        self.assertIsNotNone(self.apk.signature)

    def testPackage(self):
        self.assertIsNotNone(self.apk.get_android_manifest())
        self.assertEqual(self.apk.get_android_manifest().package, "de.rhab.helloworld")

    def testAppName(self):
        self.assertEqual(self.apk.get_app_name(), "HelloWorld")

    def testMainActivity(self):
        self.assertEqual(self.apk.get_main_activity(), 'de.rhab.helloworld.MainActivity')

    def testActivities(self):
        self.assertEqual(self.apk.get_activities(), ['de.rhab.helloworld.MainActivity'])

    def testSignatureNames(self):
        self.assertEqual(self.apk.signature.get_signature_names(), ['META-INF/CERT.RSA'])