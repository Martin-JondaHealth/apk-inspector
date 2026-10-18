#!/usr/bin/env python3
"""
APK Inspector - Core Static Analysis Engine
Analyzes Android APK packages:
- Extracts AndroidManifest.xml (package, SDK versions, permissions, components, security flags)
- Scans Dalvik bytecode (.dex) for hardcoded secrets, URLs, dangerous APIs, and SDK trackers
- Enumerates native C/C++ shared libraries (.so) and ABIs
- Evaluates OWASP Mobile Top 10 / MASVS static security rules
- Formats output conforming to the APK Inspector report contract
"""

import sys
import os
import json
import uuid
import hashlib
import re
import zipfile
from typing import Dict, Any, List, Set, Optional

try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


# Known dangerous permissions defined by Android
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.POST_NOTIFICATIONS",
}

# Regex patterns for secret detection
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": "critical",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
        "severity": "high",
    },
    {
        "name": "JSON Web Token (JWT)",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
        "severity": "high",
    },
    {
        "name": "Private RSA/EC Key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "severity": "critical",
    },
    {
        "name": "Slack Webhook",
        "pattern": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "severity": "high",
    },
    {
        "name": "Generic Hardcoded Secret/Token",
        "pattern": re.compile(r"(?:api_key|apikey|secret_key|client_secret|auth_token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']", re.IGNORECASE),
        "severity": "medium",
    },
]

# Dangerous API signatures in Dalvik/Java
DANGEROUS_APIS = [
    {
        "pattern": re.compile(r"(?:java/lang/Runtime;->exec|Runtime\.exec)"),
        "api": "Runtime.exec",
        "description": "Arbitrary command execution via shell process",
    },
    {
        "pattern": re.compile(r"java/lang/ProcessBuilder"),
        "api": "ProcessBuilder",
        "description": "Process invocation can lead to command injection",
    },
    {
        "pattern": re.compile(r"(?:dalvik/system/DexClassLoader|DexClassLoader)"),
        "api": "DexClassLoader",
        "description": "Dynamic code loading from external or untrusted storage",
    },
    {
        "pattern": re.compile(r"(?:dalvik/system/PathClassLoader|PathClassLoader)"),
        "api": "PathClassLoader",
        "description": "Dynamic classloader invocation",
    },
    {
        "pattern": re.compile(r"(?:android/webkit/WebView;->addJavascriptInterface|addJavascriptInterface)"),
        "api": "WebView.addJavascriptInterface",
        "description": "Exposing native Java bridge to WebView JavaScript",
    },
    {
        "pattern": re.compile(r"java/lang/reflect/Method;->invoke"),
        "api": "Method.invoke (Reflection)",
        "description": "Dynamic reflection invocation can bypass API restrictions",
    },
]

# Tracker package prefixes
KNOWN_TRACKERS = [
    ("Google Firebase", "com.google.firebase"),
    ("Google AdMob", "com.google.android.gms.ads"),
    ("Facebook SDK", "com.facebook.ads"),
    ("Facebook AppEvents", "com.facebook.appevents"),
    ("Adjust SDK", "com.adjust.sdk"),
    ("AppsFlyer", "com.appsflyer"),
    ("Unity Ads", "com.unity3d.ads"),
    ("Mixpanel", "com.mixpanel.android"),
    ("Flurry Analytics", "com.flurry.android"),
    ("Branch Metrics", "io.branch"),
]

# URL extraction pattern
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Ignored common schemas and namespaces
IGNORED_URL_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "https://schemas.android.com",
    "https://www.w3.org",
    "http://xmlpull.org",
    "http://www.apple.com",
)


def compute_sha256(filepath: str) -> str:
    """Calculate SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class ApkAnalyzer:
    def __init__(self, apk_path: str, analysis_id: Optional[str] = None):
        self.apk_path = os.path.abspath(apk_path)
        self.analysis_id = analysis_id or str(uuid.uuid4())
        self.file_name = os.path.basename(self.apk_path)
        self.size_bytes = os.path.getsize(self.apk_path)
        self.sha256 = compute_sha256(self.apk_path)

        self.manifest_data = {
            "package": "unknown",
            "versionName": "1.0",
            "versionCode": 1,
            "minSdk": 21,
            "targetSdk": 34,
            "permissions": [],
            "dangerousPermissions": [],
            "exportedComponents": {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
            },
        }

        self.security_data = {
            "debuggable": False,
            "allowBackup": True,
            "usesCleartextTraffic": False,
            "signingScheme": [],
            "findings": [],
        }

        self.code_insights = {
            "hardcodedUrls": [],
            "possibleSecrets": [],
            "dangerousApiCalls": [],
            "trackers": [],
        }

        self.native_data = {
            "libs": [],
            "abis": [],
        }

    def analyze(self) -> Dict[str, Any]:
        """Execute complete static analysis pipeline."""
        # 1. Enumerate Native Libraries (.so) via Zip Inspection
        self._analyze_native_libraries()

        # 2. Extract Manifest via Androguard / Fallback
        self._analyze_manifest()

        # 3. Disassemble / Scan Bytecode (DEX files)
        self._analyze_dex_bytecode()

        # 4. Run Rule Engine for Security Findings
        self._evaluate_security_rules()

        # 5. Assemble final report contract
        return {
            "analysisId": self.analysis_id,
            "apk": {
                "fileName": self.file_name,
                "sizeBytes": self.size_bytes,
                "sha256": self.sha256,
            },
            "manifest": self.manifest_data,
            "security": self.security_data,
            "codeInsights": self.code_insights,
            "native": self.native_data,
            "aiSummary": None,
        }

    def _analyze_native_libraries(self):
        """Enumerate native .so libraries and target ABIs from the APK archive."""
        libs_list = []
        abis_set = set()

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for entry in zf.namelist():
                    if entry.startswith("lib/") and entry.endswith(".so"):
                        parts = entry.split("/")
                        if len(parts) >= 3:
                            abi = parts[1]
                            lib_name = parts[2]
                            abis_set.add(abi)
                            libs_list.append({"name": lib_name, "abi": abi})

            self.native_data["libs"] = libs_list
            self.native_data["abis"] = sorted(list(abis_set))
        except Exception as e:
            # Non-fatal if native analysis fails on corrupted zip
            pass

    def _analyze_manifest(self):
        """Parse AndroidManifest.xml for package details, permissions, components, and security flags."""
        is_binary_axml = False
        raw_manifest_bytes = b""
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    raw_manifest_bytes = zf.read("AndroidManifest.xml")
                    # Android binary XML magic is 0x00080003 (3 in first byte, 8 in 3rd/4th)
                    if len(raw_manifest_bytes) >= 4 and raw_manifest_bytes[:2] == b"\x03\x00":
                        is_binary_axml = True
        except Exception:
            pass

        if is_binary_axml and ANDROGUARD_AVAILABLE:
            try:
                apk = APK(self.apk_path)
                self._populate_from_androguard(apk)
                return
            except Exception:
                pass

        # Fallback / text XML parser
        self._analyze_manifest_fallback(raw_manifest_bytes)

    def _populate_from_androguard(self, apk: "APK"):
        """Populate manifest and security details using androguard APK parser."""
        package_name = apk.get_package() or "com.example.unknown"
        version_name = apk.get_androidversion_name() or "1.0"
        version_code_str = apk.get_androidversion_code() or "1"
        try:
            version_code = int(version_code_str)
        except ValueError:
            version_code = 1

        min_sdk_str = apk.get_min_sdk_version() or "21"
        target_sdk_str = apk.get_target_sdk_version() or "34"
        try:
            min_sdk = int(min_sdk_str)
        except ValueError:
            min_sdk = 21
        try:
            target_sdk = int(target_sdk_str)
        except ValueError:
            target_sdk = 34

        declared_permissions = apk.get_permissions() or []
        dangerous = [p for p in declared_permissions if p in DANGEROUS_PERMISSIONS or any(p.endswith(f".{d}") for d in ["READ_SMS", "ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS"])]

        activities = apk.get_activities() or []
        services = apk.get_services() or []
        receivers = apk.get_receivers() or []
        providers = apk.get_providers() or []

        exported_activities = []
        exported_services = []
        exported_receivers = []
        exported_providers = []

        manifest_xml = None
        try:
            manifest_xml = apk.get_android_manifest_xml()
        except Exception:
            pass

        if manifest_xml is not None:
            ns = "{http://schemas.android.com/apk/res/android}"
            app_elem = manifest_xml.find("application")
            if app_elem is not None:
                debuggable_val = app_elem.get(f"{ns}debuggable")
                self.security_data["debuggable"] = (debuggable_val == "true" or debuggable_val == "1")

                allow_backup_val = app_elem.get(f"{ns}allowBackup")
                self.security_data["allowBackup"] = (allow_backup_val is None or allow_backup_val == "true" or allow_backup_val == "1")

                cleartext_val = app_elem.get(f"{ns}usesCleartextTraffic")
                self.security_data["usesCleartextTraffic"] = (cleartext_val == "true" or cleartext_val == "1")

                for act in app_elem.findall("activity"):
                    name = act.get(f"{ns}name")
                    exported = act.get(f"{ns}exported")
                    has_intent = act.find("intent-filter") is not None
                    if exported == "true" or (exported is None and has_intent):
                        if name:
                            exported_activities.append(name)

                for srv in app_elem.findall("service"):
                    name = srv.get(f"{ns}name")
                    exported = srv.get(f"{ns}exported")
                    has_intent = srv.find("intent-filter") is not None
                    if exported == "true" or (exported is None and has_intent):
                        if name:
                            exported_services.append(name)

                for rcv in app_elem.findall("receiver"):
                    name = rcv.get(f"{ns}name")
                    exported = rcv.get(f"{ns}exported")
                    has_intent = rcv.find("intent-filter") is not None
                    if exported == "true" or (exported is None and has_intent):
                        if name:
                            exported_receivers.append(name)

                for prv in app_elem.findall("provider"):
                    name = prv.get(f"{ns}name")
                    exported = prv.get(f"{ns}exported")
                    if exported == "true":
                        if name:
                            exported_providers.append(name)
        else:
            exported_activities = activities[:5]
            exported_services = services[:5]
            exported_receivers = receivers[:5]
            exported_providers = providers[:5]

        signing_schemes = []
        try:
            if apk.is_signed_v1():
                signing_schemes.append("v1")
            if apk.is_signed_v2():
                signing_schemes.append("v2")
            if apk.is_signed_v3():
                signing_schemes.append("v3")
        except Exception:
            signing_schemes.append("v1")

        self.manifest_data["package"] = package_name
        self.manifest_data["versionName"] = version_name
        self.manifest_data["versionCode"] = version_code
        self.manifest_data["minSdk"] = min_sdk
        self.manifest_data["targetSdk"] = target_sdk
        self.manifest_data["permissions"] = declared_permissions
        self.manifest_data["dangerousPermissions"] = dangerous
        self.manifest_data["exportedComponents"] = {
            "activities": exported_activities,
            "services": exported_services,
            "receivers": exported_receivers,
            "providers": exported_providers,
        }
        self.security_data["signingScheme"] = signing_schemes or ["v1"]

    def _analyze_manifest_fallback(self, raw_bytes: bytes = b""):
        """Fallback manifest parser supporting standard XML elements and regex."""
        try:
            if not raw_bytes:
                with zipfile.ZipFile(self.apk_path, "r") as zf:
                    if "AndroidManifest.xml" in zf.namelist():
                        raw_bytes = zf.read("AndroidManifest.xml")

            if raw_bytes:
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(raw_bytes)
                    self.manifest_data["package"] = root.attrib.get("package", "com.example.app")
                    self.manifest_data["versionName"] = root.attrib.get("{http://schemas.android.com/apk/res/android}versionName", root.attrib.get("android:versionName", "1.0"))
                    vcode = root.attrib.get("{http://schemas.android.com/apk/res/android}versionCode", root.attrib.get("android:versionCode", "1"))
                    try:
                        self.manifest_data["versionCode"] = int(vcode)
                    except ValueError:
                        self.manifest_data["versionCode"] = 1

                    sdk_elem = root.find("uses-sdk")
                    if sdk_elem is not None:
                        min_s = sdk_elem.attrib.get("{http://schemas.android.com/apk/res/android}minSdkVersion", sdk_elem.attrib.get("android:minSdkVersion", "21"))
                        tgt_s = sdk_elem.attrib.get("{http://schemas.android.com/apk/res/android}targetSdkVersion", sdk_elem.attrib.get("android:targetSdkVersion", "34"))
                        try:
                            self.manifest_data["minSdk"] = int(min_s)
                        except ValueError:
                            pass
                        try:
                            self.manifest_data["targetSdk"] = int(tgt_s)
                        except ValueError:
                            pass

                    perms = []
                    for p in root.findall("uses-permission"):
                        p_name = p.attrib.get("{http://schemas.android.com/apk/res/android}name", p.attrib.get("android:name"))
                        if p_name:
                            perms.append(p_name)
                    self.manifest_data["permissions"] = perms
                    self.manifest_data["dangerousPermissions"] = [p for p in perms if p in DANGEROUS_PERMISSIONS or any(p.endswith(f".{d}") for d in ["READ_SMS", "ACCESS_FINE_LOCATION", "CAMERA"])]

                    app = root.find("application")
                    if app is not None:
                        dbg = app.attrib.get("{http://schemas.android.com/apk/res/android}debuggable", app.attrib.get("android:debuggable"))
                        self.security_data["debuggable"] = (dbg == "true")

                        ab = app.attrib.get("{http://schemas.android.com/apk/res/android}allowBackup", app.attrib.get("android:allowBackup"))
                        self.security_data["allowBackup"] = (ab is None or ab == "true")

                        clt = app.attrib.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic", app.attrib.get("android:usesCleartextTraffic"))
                        self.security_data["usesCleartextTraffic"] = (clt == "true")

                        exp_acts = []
                        exp_srvs = []
                        exp_rcvs = []
                        exp_prvs = []

                        for act in app.findall("activity"):
                            name = act.attrib.get("{http://schemas.android.com/apk/res/android}name", act.attrib.get("android:name"))
                            exp = act.attrib.get("{http://schemas.android.com/apk/res/android}exported", act.attrib.get("android:exported"))
                            has_filter = act.find("intent-filter") is not None
                            if exp == "true" or (exp is None and has_filter):
                                if name:
                                    exp_acts.append(name)

                        for srv in app.findall("service"):
                            name = srv.attrib.get("{http://schemas.android.com/apk/res/android}name", srv.attrib.get("android:name"))
                            exp = srv.attrib.get("{http://schemas.android.com/apk/res/android}exported", srv.attrib.get("android:exported"))
                            has_filter = srv.find("intent-filter") is not None
                            if exp == "true" or (exp is None and has_filter):
                                if name:
                                    exp_srvs.append(name)

                        for rcv in app.findall("receiver"):
                            name = rcv.attrib.get("{http://schemas.android.com/apk/res/android}name", rcv.attrib.get("android:name"))
                            exp = rcv.attrib.get("{http://schemas.android.com/apk/res/android}exported", rcv.attrib.get("android:exported"))
                            has_filter = rcv.find("intent-filter") is not None
                            if exp == "true" or (exp is None and has_filter):
                                if name:
                                    exp_rcvs.append(name)

                        for prv in app.findall("provider"):
                            name = prv.attrib.get("{http://schemas.android.com/apk/res/android}name", prv.attrib.get("android:name"))
                            exp = prv.attrib.get("{http://schemas.android.com/apk/res/android}exported", prv.attrib.get("android:exported"))
                            if exp == "true":
                                if name:
                                    exp_prvs.append(name)

                        self.manifest_data["exportedComponents"] = {
                            "activities": exp_acts,
                            "services": exp_srvs,
                            "receivers": exp_rcvs,
                            "providers": exp_prvs,
                        }
                except Exception:
                    pass

            with zipfile.ZipFile(self.apk_path, "r") as zf:
                meta_inf = [n for n in zf.namelist() if n.startswith("META-INF/")]
                if any(n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC") for n in meta_inf):
                    self.security_data["signingScheme"] = ["v1"]
                else:
                    self.security_data["signingScheme"] = ["v2"]
        except Exception:
            pass

    def _analyze_dex_bytecode(self):
        """Extract strings, method invocations, and class names across all DEX bytecode files."""
        dex_strings: Set[str] = set()
        dex_methods: Set[str] = set()
        dex_classes: Set[str] = set()

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                dex_files = [f for f in zf.namelist() if f.endswith(".dex")]

                for dex_file in dex_files:
                    dex_bytes = zf.read(dex_file)

                    if ANDROGUARD_AVAILABLE:
                        try:
                            dvm = DalvikVMFormat(dex_bytes)
                            for s in dvm.get_strings():
                                if isinstance(s, bytes):
                                    s = s.decode("utf-8", errors="ignore")
                                dex_strings.add(str(s))
                            for m in dvm.get_methods():
                                c_name = str(m.get_class_name())
                                m_name = str(m.get_name())
                                dex_methods.add(f"{c_name}->{m_name}")
                            for c in dvm.get_classes():
                                dex_classes.add(str(c.get_name()))
                            continue
                        except Exception:
                            pass

                    # Direct string extraction fallback from DEX binary format
                    extracted = self._extract_strings_from_dex_bytes(dex_bytes)
                    dex_strings.update(extracted)

        except Exception:
            pass

        # 1. URL and IP Detection
        urls_found = set()
        for s in dex_strings:
            for url in URL_PATTERN.findall(s):
                if not any(url.startswith(prefix) for prefix in IGNORED_URL_PREFIXES):
                    urls_found.add(url)

        self.code_insights["hardcodedUrls"] = sorted(list(urls_found))[:25]

        # 2. Secret Pattern Scanning
        secrets_found = []
        for s in dex_strings:
            for secret_rule in SECRET_PATTERNS:
                matches = secret_rule["pattern"].findall(s)
                for match in matches:
                    matched_str = match if isinstance(match, str) else match[0]
                    # Mask the secret for safe reporting
                    masked = matched_str[:4] + "*" * (max(0, len(matched_str) - 8)) + matched_str[-4:] if len(matched_str) > 8 else "****"
                    secrets_found.append({
                        "pattern": secret_rule["name"],
                        "location": "classes.dex",
                        "evidence": masked,
                        "severity": secret_rule["severity"],
                    })

        self.code_insights["possibleSecrets"] = secrets_found[:20]

        # 3. Dangerous API Invocations
        apis_found = set()
        combined_code_signatures = dex_strings.union(dex_methods)
        for sig in combined_code_signatures:
            for api_rule in DANGEROUS_APIS:
                if api_rule["pattern"].search(sig):
                    apis_found.add(api_rule["api"])

        self.code_insights["dangerousApiCalls"] = sorted(list(apis_found))

        # 4. Tracker SDK Detection
        trackers_detected = set()
        for item in dex_strings.union(dex_classes):
            for tracker_name, tracker_prefix in KNOWN_TRACKERS:
                if tracker_prefix in item:
                    trackers_detected.add(tracker_name)

        self.code_insights["trackers"] = sorted(list(trackers_detected))

    def _extract_strings_from_dex_bytes(self, data: bytes) -> Set[str]:
        """Extract null-terminated and UTF-8 strings from binary DEX buffer."""
        strings = set()
        # Regex to find printable ASCII/UTF-8 strings of length >= 4
        printable_regex = re.compile(rb"[\x20-\x7E]{4,}")
        for match in printable_regex.finditer(data):
            try:
                s = match.group(0).decode("utf-8")
                strings.add(s)
            except Exception:
                continue
        return strings

    def _evaluate_security_rules(self):
        """Rule engine that evaluates findings against OWASP MASVS and Android best practices."""
        findings = []

        # Rule 1: Debuggable application flag
        if self.security_data.get("debuggable", False):
            findings.append({
                "id": "DEBUGGABLE_APP",
                "severity": "high",
                "title": "Application Is Debuggable",
                "evidence": 'android:debuggable is set to "true" in AndroidManifest.xml',
                "recommendation": "Disable android:debuggable in production release builds to prevent process memory inspection via JDWP/jdb.",
                "owaspCategory": "MASVS-RESILIENCE",
            })

        # Rule 2: Backup enabled
        if self.security_data.get("allowBackup", False):
            findings.append({
                "id": "ALLOW_BACKUP",
                "severity": "low",
                "title": "Application Data Backup Enabled",
                "evidence": 'android:allowBackup is enabled, permitting "adb backup" extraction',
                "recommendation": 'Set android:allowBackup="false" or configure a strict backup_rules.xml to prevent sensitive database and token leakage.',
                "owaspCategory": "MASVS-STORAGE",
            })

        # Rule 3: Cleartext HTTP traffic
        has_http_urls = any(url.startswith("http://") for url in self.code_insights.get("hardcodedUrls", []))
        if self.security_data.get("usesCleartextTraffic", False) or has_http_urls:
            findings.append({
                "id": "CLEARTEXT_TRAFFIC",
                "severity": "medium",
                "title": "Cleartext HTTP Traffic Allowed",
                "evidence": (
                    "android:usesCleartextTraffic is true"
                    if self.security_data.get("usesCleartextTraffic")
                    else f"Hardcoded unencrypted HTTP URLs detected ({len(self.code_insights.get('hardcodedUrls', []))} URLs found)"
                ),
                "recommendation": "Enforce TLS/HTTPS across all network communications and define a strict network_security_config.xml.",
                "owaspCategory": "MASVS-NETWORK",
            })

        # Rule 4: Dangerous runtime permissions
        dangerous_perms = self.manifest_data.get("dangerousPermissions", [])
        if len(dangerous_perms) > 0:
            findings.append({
                "id": "DANGEROUS_PERMISSIONS",
                "severity": "medium",
                "title": "Excessive or Dangerous Permissions Requested",
                "evidence": f"Application requests {len(dangerous_perms)} sensitive permissions: {', '.join(dangerous_perms[:6])}",
                "recommendation": "Apply the principle of least privilege. Request permissions dynamically at runtime only when strictly needed.",
                "owaspCategory": "MASVS-PLATFORM",
            })

        # Rule 5: Exported components without permission guards
        exported = self.manifest_data.get("exportedComponents", {})
        total_exported = sum(len(v) for v in exported.values())
        if total_exported > 0:
            findings.append({
                "id": "EXPORTED_COMPONENTS",
                "severity": "medium",
                "title": "Exported Android Components Exposed",
                "evidence": f"Found {total_exported} exported components (Activities: {len(exported.get('activities', []))}, Services: {len(exported.get('services', []))}, Receivers: {len(exported.get('receivers', []))}, Providers: {len(exported.get('providers', []))})",
                "recommendation": 'Explicitly set android:exported="false" on non-public components, or guard them with signature-level custom permissions.',
                "owaspCategory": "MASVS-PLATFORM",
            })

        # Rule 6: Outdated Target SDK
        target_sdk = self.manifest_data.get("targetSdk", 34)
        if target_sdk < 31:
            findings.append({
                "id": "OUTDATED_TARGET_SDK",
                "severity": "medium",
                "title": f"Outdated Target SDK ({target_sdk})",
                "evidence": f"Application targets API level {target_sdk}, which lacks modern Android security restrictions.",
                "recommendation": "Upgrade targetSdkVersion to 34+ to inherit platform security enhancements (scoped storage, explicit exported flags).",
                "owaspCategory": "MASVS-PLATFORM",
            })

        # Rule 7: Hardcoded secrets in bytecode
        secrets = self.code_insights.get("possibleSecrets", [])
        if len(secrets) > 0:
            crit_count = sum(1 for s in secrets if s.get("severity") in ("critical", "high"))
            findings.append({
                "id": "HARDCODED_SECRETS",
                "severity": "critical" if crit_count > 0 else "high",
                "title": "Hardcoded Secrets Detected in Bytecode",
                "evidence": f"Found {len(secrets)} potential hardcoded credentials ({', '.join(set(s['pattern'] for s in secrets))})",
                "recommendation": "Remove embedded credentials from bytecode. Store sensitive API keys in backend vaults or use OAuth client credentials flow.",
                "owaspCategory": "MASVS-STORAGE",
            })

        # Rule 8: Dangerous API calls (Dynamic execution, reflection, exec)
        dangerous_apis = self.code_insights.get("dangerousApiCalls", [])
        if len(dangerous_apis) > 0:
            findings.append({
                "id": "DANGEROUS_APIS",
                "severity": "high" if any(a in ("Runtime.exec", "DexClassLoader") for a in dangerous_apis) else "medium",
                "title": "Dangerous Java/Dalvik APIs Invoked",
                "evidence": f"Bytecode invokes potentially hazardous APIs: {', '.join(dangerous_apis)}",
                "recommendation": "Avoid invoking shell processes or dynamic DEX classloaders. Review reflection calls for integrity.",
                "owaspCategory": "MASVS-CODE",
            })

        # Rule 9: Native C/C++ Binaries Present
        native_libs = self.native_data.get("libs", [])
        if len(native_libs) > 0:
            findings.append({
                "id": "NATIVE_CODE_LAYER",
                "severity": "info",
                "title": "Native C/C++ Libraries Bundled",
                "evidence": f"Bundled {len(native_libs)} native .so shared libraries across ABIs: {', '.join(self.native_data.get('abis', []))}",
                "recommendation": "Audit native JNI boundaries for memory safety (buffer overflows, use-after-free) and compile with stack protectors (-fstack-protector-strong) and ASLR.",
                "owaspCategory": "MASVS-CODE",
            })

        # Rule 10: Signing scheme checks
        signing = self.security_data.get("signingScheme", [])
        if "v2" not in signing and "v3" not in signing:
            findings.append({
                "id": "WEAK_SIGNING_SCHEME",
                "severity": "medium",
                "title": "Legacy JAR Signature Scheme (v1 only)",
                "evidence": f"APK uses legacy signing schemes: {', '.join(signing) or 'unverified'}",
                "recommendation": "Sign the APK with APK Signature Scheme v2/v3 to prevent ZIP metadata tampering (Janus vulnerability).",
                "owaspCategory": "MASVS-RESILIENCE",
            })

        self.security_data["findings"] = findings


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_apk> [optional_analysis_id]", file=sys.stderr)
        sys.exit(1)

    apk_path = sys.argv[1]
    analysis_id = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(apk_path):
        print(json.dumps({"error": f"File not found: {apk_path}"}), file=sys.stderr)
        sys.exit(2)

    analyzer = ApkAnalyzer(apk_path, analysis_id)
    report = analyzer.analyze()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
