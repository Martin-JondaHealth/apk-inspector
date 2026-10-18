import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AiService } from './ai.service';
import { ApkReportDto } from '../analyzer/dto/report.dto';

describe('AiService', () => {
  let service: AiService;

  const mockReport: ApkReportDto = {
    analysisId: 'test-uuid-5678',
    apk: {
      fileName: 'target-release.apk',
      sizeBytes: 20480,
      sha256: 'deadbeef1234',
    },
    manifest: {
      package: 'com.target.healthcare',
      versionName: '2.0.1',
      versionCode: 20,
      minSdk: 24,
      targetSdk: 33,
      permissions: ['android.permission.INTERNET', 'android.permission.CAMERA'],
      dangerousPermissions: ['android.permission.CAMERA'],
      exportedComponents: {
        activities: ['.MainActivity'],
        services: ['.SyncService'],
        receivers: [],
        providers: [],
      },
    },
    security: {
      debuggable: false,
      allowBackup: true,
      usesCleartextTraffic: false,
      signingScheme: ['v2'],
      findings: [
        {
          id: 'ALLOW_BACKUP',
          severity: 'low',
          title: 'Application Data Backup Enabled',
          evidence: 'allowBackup is true',
          recommendation: 'Set to false',
        },
      ],
    },
    codeInsights: {
      hardcodedUrls: ['https://api.healthcare.org/v1'],
      possibleSecrets: [],
      dangerousApiCalls: [],
      trackers: ['Google Firebase'],
    },
    native: {
      libs: [],
      abis: [],
    },
    aiSummary: null,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AiService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue(null), // No external API key in unit test
          },
        },
      ],
    }).compile();

    service = module.get<AiService>(AiService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should generate high quality deterministic summary when no API keys are present', async () => {
    const res = await service.generateRiskSummary(mockReport);
    expect(res).toBeDefined();
    expect(res.model).toBe('rule-based-security-heuristics');
    expect(res.summary).toContain('Executive Security Audit');
    expect(res.summary).toContain('com.target.healthcare');
    expect(res.summary).toContain('Attack Surface Analysis');
    expect(res.summary).toContain('Recommended Remediation Actions');
  });
});
