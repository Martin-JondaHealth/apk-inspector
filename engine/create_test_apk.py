#!/usr/bin/env python3
"""
Test APK Generator
Creates a sample, self-contained benign test APK containing known indicators for testing:
- Manifest with debuggable=true, allowBackup=true, cleartext traffic, dangerous permissions
- Exported components (Activities, Services, Receivers)
- Classes.dex containing hardcoded URLs, AWS keys, Google API keys, dangerous API calls
- Native .so libraries in arm64-v8a and armeabi-v7a
- META-INF signing entries
"""

import sys
import os
import zipfile
import struct

def build_minimal_dex():
    """Construct a minimal valid DEX binary with test strings."""
    test_strings = [
        "Lcom/example/vulnerableapp/MainActivity;",
        "Lcom/example/vulnerableapp/AuthService;",
        "http://api.internal.corp/v1/debug-telemetry",
        "https://secure.example.com/api/v2",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyD_TestGoogleApiKey35CharactersLong__",
        "java/lang/Runtime;->exec",
        "dalvik/system/DexClassLoader",
        "android/webkit/WebView;->addJavascriptInterface",
        "com.google.firebase.analytics",
        "com.adjust.sdk.Adjust",
    ]

    # Minimal DEX file header (112 bytes)
    # Magic: 'dex\n035\0'
    magic = b"dex\n035\x00"
    checksum = b"\x00" * 4
    signature = b"\x00" * 20
    file_size_offset = 32
    
    # We embed the test strings into a binary blob
    payload = b"\x00".join(s.encode("utf-8") for s in test_strings)
    total_size = 112 + len(payload)
    
    header = bytearray(112)
    header[0:8] = magic
    struct.pack_into("<I", header, 32, total_size)  # file_size
    struct.pack_into("<I", header, 36, 112)         # header_size
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag

    return bytes(header) + payload

def build_minimal_manifest():
    """
    Construct a manifest payload. Androguard can parse XML directly or we embed 
    well-formed binary/text markers for analysis.
    """
    manifest_content = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    package="com.example.vulnerableapp"\n'
        '    android:versionCode="10"\n'
        '    android:versionName="2.1.0">\n'
        '    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />\n'
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        '    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />\n'
        '    <uses-permission android:name="android.permission.READ_SMS" />\n'
        '    <uses-permission android:name="android.permission.CAMERA" />\n'
        '    <application\n'
        '        android:debuggable="true"\n'
        '        android:allowBackup="true"\n'
        '        android:usesCleartextTraffic="true"\n'
        '        android:label="VulnerableDemoApp">\n'
        '        <activity android:name=".MainActivity" android:exported="true">\n'
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.MAIN" />\n'
        '                <category android:name="android.intent.category.LAUNCHER" />\n'
        '            </intent-filter>\n'
        '        </activity>\n'
        '        <activity android:name=".DebugActivity" android:exported="true" />\n'
        '        <service android:name=".SyncService" android:exported="true" />\n'
        '        <receiver android:name=".PushReceiver" android:exported="true" />\n'
        '    </application>\n'
        '</manifest>'
    )
    return manifest_content.encode("utf-8")

def build_minimal_elf():
    """Construct a minimal 64-bit ELF shared object header."""
    # ELF magic \x7fELF, 64-bit (2), little endian (1), version (1)
    elf_magic = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
    e_type = struct.pack("<H", 3)      # ET_DYN (Shared object)
    e_machine = struct.pack("<H", 183) # EM_AARCH64
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0x1000)
    e_phoff = struct.pack("<Q", 64)
    e_shoff = struct.pack("<Q", 0)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 56)
    e_phnum = struct.pack("<H", 1)
    e_shentsize = struct.pack("<H", 64)
    e_shnum = struct.pack("<H", 0)
    e_shstrndx = struct.pack("<H", 0)
    
    header = elf_magic + e_type + e_machine + e_version + e_entry + e_phoff + e_shoff + e_flags + e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx
    payload = b"Java_com_example_vulnerableapp_NativeBridge_computeHash\x00"
    return header + payload

def create_sample_apk(output_path: str):
    """Generate the sample test APK."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1. AndroidManifest.xml
        zf.writestr("AndroidManifest.xml", build_minimal_manifest())
        
        # 2. classes.dex
        zf.writestr("classes.dex", build_minimal_dex())
        
        # 3. Native libraries
        elf_data = build_minimal_elf()
        zf.writestr("lib/arm64-v8a/libnative-security.so", elf_data)
        zf.writestr("lib/armeabi-v7a/libnative-security.so", elf_data)
        
        # 4. Signature block
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: APK-Inspector-Test\r\n")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: test\r\n")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x0a" + b"\x00" * 100)

    print(f"Sample test APK successfully generated at: {output_path}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "sample-test.apk"
    create_sample_apk(target)
