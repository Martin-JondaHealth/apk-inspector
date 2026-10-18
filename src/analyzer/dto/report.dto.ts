import { ApiProperty } from '@nestjs/swagger';

export class ApkMetadataDto {
  @ApiProperty({ example: 'app-release.apk', description: 'Original uploaded filename' })
  fileName: string;

  @ApiProperty({ example: 1548290, description: 'File size in bytes' })
  sizeBytes: number;

  @ApiProperty({ example: 'd4877fe201bf6e9bbd94e2840af6d6da27f9331568bd7e9e14cb5b0d4745ef60', description: 'SHA-256 cryptographic hash of APK' })
  sha256: string;
}

export class ExportedComponentsDto {
  @ApiProperty({ example: ['.MainActivity', '.DebugActivity'], description: 'Exported activities exposed to other apps' })
  activities: string[];

  @ApiProperty({ example: ['.SyncService'], description: 'Exported background services' })
  services: string[];

  @ApiProperty({ example: ['.PushReceiver'], description: 'Exported broadcast receivers' })
  receivers: string[];

  @ApiProperty({ example: [], description: 'Exported content providers' })
  providers: string[];
}

export class ManifestDto {
  @ApiProperty({ example: 'com.example.app', description: 'Android package identifier' })
  package: string;

  @ApiProperty({ example: '1.2.3', description: 'User-facing version name' })
  versionName: string;

  @ApiProperty({ example: 10, description: 'Internal version code' })
  versionCode: number;

  @ApiProperty({ example: 21, description: 'Minimum supported Android API level' })
  minSdk: number;

  @ApiProperty({ example: 34, description: 'Target Android API level' })
  targetSdk: number;

  @ApiProperty({ example: ['android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION'], description: 'All declared permissions' })
  permissions: string[];

  @ApiProperty({ example: ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_SMS'], description: 'Sensitive runtime permissions requiring user approval' })
  dangerousPermissions: string[];

  @ApiProperty({ type: ExportedComponentsDto, description: 'Components accessible by external applications' })
  exportedComponents: ExportedComponentsDto;
}

export class SecurityFindingDto {
  @ApiProperty({ example: 'DEBUGGABLE_APP', description: 'Rule finding identifier' })
  id: string;

  @ApiProperty({ example: 'high', enum: ['critical', 'high', 'medium', 'low', 'info'], description: 'Risk severity level' })
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';

  @ApiProperty({ example: 'Application Is Debuggable', description: 'Human-readable title' })
  title: string;

  @ApiProperty({ example: 'android:debuggable is set to true in AndroidManifest.xml', description: 'Technical evidence observed' })
  evidence: string;

  @ApiProperty({ example: 'Disable android:debuggable in production release builds', description: 'Actionable remediation steps' })
  recommendation: string;

  @ApiProperty({ example: 'MASVS-RESILIENCE', required: false, description: 'OWASP MASVS category' })
  owaspCategory?: string;
}

export class SecurityDto {
  @ApiProperty({ example: false, description: 'Whether the debug flag is enabled in the manifest' })
  debuggable: boolean;

  @ApiProperty({ example: true, description: 'Whether application data can be backed up via adb' })
  allowBackup: boolean;

  @ApiProperty({ example: true, description: 'Whether plain unencrypted HTTP traffic is permitted' })
  usesCleartextTraffic: boolean;

  @ApiProperty({ example: ['v1', 'v2'], description: 'Detected APK signature schemes' })
  signingScheme: string[];

  @ApiProperty({ type: [SecurityFindingDto], description: 'List of all detected security findings' })
  findings: SecurityFindingDto[];
}

export class SecretFindingDto {
  @ApiProperty({ example: 'AWS Access Key', description: 'Identified secret pattern category' })
  pattern: string;

  @ApiProperty({ example: 'classes.dex', description: 'Binary source location' })
  location: string;

  @ApiProperty({ example: 'AKIA************MPLE', description: 'Redacted evidence snippet' })
  evidence: string;

  @ApiProperty({ example: 'critical', enum: ['critical', 'high', 'medium', 'low', 'info'] })
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export class CodeInsightsDto {
  @ApiProperty({ example: ['http://api.internal.corp/debug', 'https://api.example.com'], description: 'Hardcoded URLs and endpoints detected in bytecode' })
  hardcodedUrls: string[];

  @ApiProperty({ type: [SecretFindingDto], description: 'Potential API keys, tokens, or credentials extracted from bytecode' })
  possibleSecrets: SecretFindingDto[];

  @ApiProperty({ example: ['Runtime.exec', 'DexClassLoader'], description: 'Potentially risky Dalvik/Java API invocations' })
  dangerousApiCalls: string[];

  @ApiProperty({ example: ['Google Firebase', 'Adjust SDK'], description: 'Detected third-party ad and tracking analytics SDKs' })
  trackers: string[];
}

export class NativeLibDto {
  @ApiProperty({ example: 'libsecurity_native.so', description: 'Filename of shared native library' })
  name: string;

  @ApiProperty({ example: 'arm64-v8a', description: 'Target CPU architecture ABI' })
  abi: string;
}

export class NativeDto {
  @ApiProperty({ type: [NativeLibDto], description: 'List of bundled .so native libraries' })
  libs: NativeLibDto[];

  @ApiProperty({ example: ['arm64-v8a', 'armeabi-v7a'], description: 'Distinct CPU ABIs supported by the package' })
  abis: string[];
}

export class ApkReportDto {
  @ApiProperty({ example: '2a1bb0fc-4ea3-4d2c-b664-0e57c1b86d88', description: 'Unique analysis job UUID' })
  analysisId: string;

  @ApiProperty({ type: ApkMetadataDto, description: 'File metadata' })
  apk: ApkMetadataDto;

  @ApiProperty({ type: ManifestDto, description: 'Manifest configuration and Android components' })
  manifest: ManifestDto;

  @ApiProperty({ type: SecurityDto, description: 'Security posture and OWASP MASVS findings' })
  security: SecurityDto;

  @ApiProperty({ type: CodeInsightsDto, description: 'Static bytecode decompilation insights' })
  codeInsights: CodeInsightsDto;

  @ApiProperty({ type: NativeDto, description: 'Native C/C++ architecture details' })
  native: NativeDto;

  @ApiProperty({ example: null, nullable: true, description: 'AI-generated plain-English risk summary' })
  aiSummary: string | null;
}
