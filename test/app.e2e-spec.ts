import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as path from 'path';
import * as fs from 'fs';
import { AppModule } from '../src/app.module';

describe('APK Inspector (e2e)', () => {
  let app: INestApplication;
  let analysisId: string;
  const sampleApkPath = path.join(__dirname, '..', 'sample-test.apk');

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('GET /health - should return healthy system status', async () => {
    const res = await request(app.getHttpServer()).get('/health').expect(200);

    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('apk-inspector');
    expect(res.body.environment).toBeDefined();
    expect(res.body.environment.engineReady).toBe(true);
  });

  it('POST /analyze - should upload and analyze sample test APK', async () => {
    expect(fs.existsSync(sampleApkPath)).toBe(true);

    const res = await request(app.getHttpServer())
      .post('/analyze')
      .attach('file', sampleApkPath)
      .expect(200);

    expect(res.body.status).toBe('completed');
    expect(res.body.analysisId).toBeDefined();
    expect(res.body.reportUrl).toContain('/report/');

    analysisId = res.body.analysisId;
  }, 30000);

  it('GET /report/:id - should return complete structured security report matching contract', async () => {
    expect(analysisId).toBeDefined();

    const res = await request(app.getHttpServer())
      .get(`/report/${analysisId}`)
      .expect(200);

    // Verify Output Contract
    expect(res.body.analysisId).toBe(analysisId);
    expect(res.body.apk).toBeDefined();
    expect(res.body.apk.fileName).toBeDefined();
    expect(res.body.apk.sha256).toBeDefined();

    expect(res.body.manifest).toBeDefined();
    expect(res.body.manifest.package).toBe('com.example.vulnerableapp');
    expect(res.body.manifest.permissions).toContain('android.permission.INTERNET');
    expect(res.body.manifest.dangerousPermissions).toContain('android.permission.READ_SMS');
    expect(res.body.manifest.exportedComponents.activities).toBeDefined();

    expect(res.body.security).toBeDefined();
    expect(res.body.security.debuggable).toBe(true);
    expect(res.body.security.allowBackup).toBe(true);
    expect(res.body.security.usesCleartextTraffic).toBe(true);
    expect(Array.isArray(res.body.security.findings)).toBe(true);
    expect(res.body.security.findings.length).toBeGreaterThan(0);

    // Check specific finding structure
    const debugFinding = res.body.security.findings.find((f: any) => f.id === 'DEBUGGABLE_APP');
    expect(debugFinding).toBeDefined();
    expect(debugFinding.severity).toBe('high');
    expect(debugFinding.recommendation).toBeDefined();

    expect(res.body.codeInsights).toBeDefined();
    expect(res.body.codeInsights.hardcodedUrls.length).toBeGreaterThan(0);
    expect(res.body.codeInsights.dangerousApiCalls).toContain('Runtime.exec');

    expect(res.body.native).toBeDefined();
    expect(res.body.native.abis).toContain('arm64-v8a');
  });

  it('GET /report/:id/summary - should return condensed severity breakdown and security grade', async () => {
    const res = await request(app.getHttpServer())
      .get(`/report/${analysisId}/summary`)
      .expect(200);

    expect(res.body.analysisId).toBe(analysisId);
    expect(res.body.package).toBe('com.example.vulnerableapp');
    expect(res.body.securityGrade).toBeDefined();
    expect(res.body.findingsCount).toBeDefined();
    expect(res.body.findingsCount.total).toBeGreaterThan(0);
    expect(Array.isArray(res.body.topRisks)).toBe(true);
  });

  it('POST /summarize/:id - should return executive AI/heuristic risk summary', async () => {
    const res = await request(app.getHttpServer())
      .post(`/summarize/${analysisId}`)
      .expect(200);

    expect(res.body.analysisId).toBe(analysisId);
    expect(res.body.summary).toBeDefined();
    expect(res.body.summary).toContain('Executive Security Audit');
    expect(res.body.model).toBeDefined();
  });

  it('GET /reports - should list recent analyses', async () => {
    const res = await request(app.getHttpServer())
      .get('/reports')
      .expect(200);

    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body.some((r: any) => r.analysisId === analysisId)).toBe(true);
  });

  it('GET /report/:id - should return 404 for unknown UUID', async () => {
    await request(app.getHttpServer())
      .get('/report/00000000-0000-0000-0000-000000000000')
      .expect(404);
  });

  it('POST /analyze - should reject non-APK files', async () => {
    await request(app.getHttpServer())
      .post('/analyze')
      .attach('file', Buffer.from('FAKE TEXT FILE'), 'fake.apk')
      .expect(400);
  });
});
