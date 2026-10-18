import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { AnalyzerService } from './analyzer.service';
import { AiService } from '../ai/ai.service';
import { ApkReportDto } from './dto/report.dto';

import { PrismaService } from '../prisma/prisma.service';

describe('AnalyzerService', () => {
  let service: AnalyzerService;
  let aiService: AiService;

  const mockReport: ApkReportDto = {
    analysisId: 'test-uuid-1234',
    apk: {
      fileName: 'app.apk',
      sizeBytes: 10240,
      sha256: 'abc123def456',
    },
    manifest: {
      package: 'com.example.test',
      versionName: '1.0.0',
      versionCode: 1,
      minSdk: 21,
      targetSdk: 34,
      permissions: ['android.permission.INTERNET'],
      dangerousPermissions: ['android.permission.READ_SMS'],
      exportedComponents: {
        activities: ['.MainActivity'],
        services: [],
        receivers: [],
        providers: [],
      },
    },
    security: {
      debuggable: true,
      allowBackup: true,
      usesCleartextTraffic: true,
      signingScheme: ['v1'],
      findings: [
        {
          id: 'DEBUGGABLE_APP',
          severity: 'high',
          title: 'Application Is Debuggable',
          evidence: 'android:debuggable is true',
          recommendation: 'Disable debuggable flag',
        },
        {
          id: 'HARDCODED_SECRETS',
          severity: 'critical',
          title: 'Hardcoded Secrets Detected',
          evidence: 'AKIA...',
          recommendation: 'Remove keys',
        },
      ],
    },
    codeInsights: {
      hardcodedUrls: ['http://api.internal/test'],
      possibleSecrets: [],
      dangerousApiCalls: ['Runtime.exec'],
      trackers: ['Google Firebase'],
    },
    native: {
      libs: [{ name: 'libtest.so', abi: 'arm64-v8a' }],
      abis: ['arm64-v8a'],
    },
    aiSummary: null,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalyzerService,
        {
          provide: AiService,
          useValue: {
            generateRiskSummary: jest.fn().mockResolvedValue({
              summary: 'Mock executive summary',
              model: 'test-model',
            }),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            isConnected: false,
            analysisReport: {
              findMany: jest.fn().mockResolvedValue([]),
              findUnique: jest.fn().mockResolvedValue(null),
              upsert: jest.fn().mockResolvedValue({}),
              update: jest.fn().mockResolvedValue({}),
            },
          },
        },
      ],
    }).compile();

    service = module.get<AnalyzerService>(AnalyzerService);
    aiService = module.get<AiService>(AiService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getReport and caching', () => {
    it('should throw NotFoundException for non-existent report ID', () => {
      expect(() => service.getReport('non-existent-id')).toThrow(NotFoundException);
    });

    it('should return report if present in cache', () => {
      // Manually set in cache for testing
      (service as any).reportsCache.set(mockReport.analysisId, mockReport);
      const res = service.getReport(mockReport.analysisId);
      expect(res.analysisId).toBe(mockReport.analysisId);
      expect(res.manifest.package).toBe('com.example.test');
    });
  });

  describe('getSummary', () => {
    it('should calculate grade and count findings correctly', () => {
      (service as any).reportsCache.set(mockReport.analysisId, mockReport);
      const summary = service.getSummary(mockReport.analysisId);

      expect(summary.analysisId).toBe(mockReport.analysisId);
      expect(summary.package).toBe('com.example.test');
      expect(summary.findingsCount.critical).toBe(1);
      expect(summary.findingsCount.high).toBe(1);
      expect(summary.findingsCount.total).toBe(2);
      expect(summary.securityGrade).toBe('F'); // Critical finding triggers F grade
      expect(summary.topRisks).toContain('Hardcoded Secrets Detected');
    });
  });

  describe('file validation', () => {
    it('should reject files missing ZIP magic bytes', async () => {
      const invalidFile: any = {
        buffer: Buffer.from('NOT_A_ZIP_FILE'),
        originalname: 'fake.apk',
      };

      await expect(service.analyzeApk(invalidFile)).rejects.toThrow(BadRequestException);
    });
  });
});
