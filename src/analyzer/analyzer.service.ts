import {
  Injectable,
  NotFoundException,
  BadRequestException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import { ApkReportDto } from './dto/report.dto';
import { ReportSummaryDto } from './dto/summary.dto';
import { AnalyzeResponseDto, AiSummaryResponseDto } from './dto/analyze-response.dto';
import { AiService } from '../ai/ai.service';

const execFileAsync = promisify(execFile);

@Injectable()
export class AnalyzerService {
  private readonly logger = new Logger(AnalyzerService.name);
  private readonly reportsCache = new Map<string, ApkReportDto>();
  private readonly baseDir = process.cwd();
  private readonly uploadsDir = path.join(this.baseDir, 'uploads');
  private readonly reportsDir = path.join(this.baseDir, 'reports');
  private readonly engineScript = path.join(this.baseDir, 'engine', 'analyzer.py');

  constructor(private readonly aiService: AiService) {
    fs.mkdirSync(this.uploadsDir, { recursive: true });
    fs.mkdirSync(this.reportsDir, { recursive: true });
    this.loadPersistedReports();
  }

  private getPythonExecutable(): string {
    const venvPython = path.join(this.baseDir, '.venv', 'bin', 'python');
    if (fs.existsSync(venvPython)) {
      return venvPython;
    }
    return 'python3';
  }

  private loadPersistedReports(): void {
    try {
      const files = fs.readdirSync(this.reportsDir);
      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = fs.readFileSync(path.join(this.reportsDir, file), 'utf-8');
          const report: ApkReportDto = JSON.parse(content);
          if (report && report.analysisId) {
            this.reportsCache.set(report.analysisId, report);
          }
        }
      }
      this.logger.log(`Loaded ${this.reportsCache.size} cached security reports from disk.`);
    } catch (err) {
      this.logger.warn(`Could not load existing reports from disk: ${err.message}`);
    }
  }

  async analyzeApk(file: Express.Multer.File): Promise<AnalyzeResponseDto> {
    if (!file) {
      throw new BadRequestException('No APK file uploaded. Please provide a multipart .apk file under field "file".');
    }

    // Validate ZIP/APK magic header (PK\x03\x04)
    if (file.buffer.length < 4 || file.buffer[0] !== 0x50 || file.buffer[1] !== 0x4b || file.buffer[2] !== 0x03 || file.buffer[3] !== 0x04) {
      throw new BadRequestException('Invalid file format. The uploaded file is not a valid Android APK archive (missing ZIP magic header).');
    }

    const analysisId = uuidv4();
    const safeOriginalName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    const uploadFilePath = path.join(this.uploadsDir, `${analysisId}_${safeOriginalName}`);

    fs.writeFileSync(uploadFilePath, file.buffer);

    try {
      const report = await this.runStaticAnalysis(uploadFilePath, analysisId);
      this.reportsCache.set(analysisId, report);

      // Persist report JSON
      const reportFilePath = path.join(this.reportsDir, `${analysisId}.json`);
      fs.writeFileSync(reportFilePath, JSON.stringify(report, null, 2), 'utf-8');

      return {
        analysisId,
        status: 'completed',
        message: 'APK static analysis completed successfully.',
        reportUrl: `/report/${analysisId}`,
      };
    } catch (err) {
      this.logger.error(`Analysis failed for ${file.originalname}: ${err.message}`, err.stack);
      throw new InternalServerErrorException(`Static analysis pipeline failed: ${err.message}`);
    } finally {
      // Clean up uploaded APK archive to conserve disk storage
      if (fs.existsSync(uploadFilePath)) {
        try {
          fs.unlinkSync(uploadFilePath);
        } catch {
          // Ignore cleanup errors
        }
      }
    }
  }

  async runStaticAnalysis(apkPath: string, analysisId: string): Promise<ApkReportDto> {
    const pythonExe = this.getPythonExecutable();
    this.logger.log(`Executing analyzer engine [${pythonExe}] on ${apkPath} with ID ${analysisId}`);

    const { stdout, stderr } = await execFileAsync(pythonExe, [this.engineScript, apkPath, analysisId], {
      maxBuffer: 50 * 1024 * 1024,
    });

    if (stderr && !stdout) {
      throw new Error(`Engine error: ${stderr}`);
    }

    try {
      const parsed: ApkReportDto = JSON.parse(stdout);
      return parsed;
    } catch (err) {
      throw new Error(`Failed to parse engine output as JSON: ${err.message}. Raw output: ${stdout.slice(0, 500)}`);
    }
  }

  getReport(analysisId: string): ApkReportDto {
    const report = this.reportsCache.get(analysisId);
    if (!report) {
      throw new NotFoundException(`Analysis report with ID "${analysisId}" not found.`);
    }
    return report;
  }

  getSummary(analysisId: string): ReportSummaryDto {
    const report = this.getReport(analysisId);

    const findingsCount = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: report.security.findings.length,
    };

    const topRisks: string[] = [];

    for (const finding of report.security.findings) {
      if (finding.severity in findingsCount) {
        findingsCount[finding.severity]++;
      }
      if (['critical', 'high'].includes(finding.severity) && topRisks.length < 5) {
        topRisks.push(finding.title);
      }
    }

    // Determine security grade
    let securityGrade = 'A';
    if (findingsCount.critical > 0) {
      securityGrade = 'F';
    } else if (findingsCount.high > 1) {
      securityGrade = 'D';
    } else if (findingsCount.high === 1 || findingsCount.medium > 2) {
      securityGrade = 'C';
    } else if (findingsCount.medium > 0) {
      securityGrade = 'B';
    }

    return {
      analysisId: report.analysisId,
      package: report.manifest.package,
      versionName: report.manifest.versionName,
      fileName: report.apk.fileName,
      securityGrade,
      findingsCount,
      topRisks: topRisks.length > 0 ? topRisks : ['No critical or high severity risks detected'],
    };
  }

  async getAiSummary(analysisId: string, force: boolean = false): Promise<AiSummaryResponseDto> {
    const report = this.getReport(analysisId);

    // Only return cached summary if not forcing and summary is not truncated (< 200 chars)
    if (report.aiSummary && !force && report.aiSummary.length > 200) {
      return {
        analysisId,
        summary: report.aiSummary,
        model: 'cached',
      };
    }

    const { summary, model } = await this.aiService.generateRiskSummary(report);
    report.aiSummary = summary;
    this.reportsCache.set(analysisId, report);

    // Update persisted JSON
    const reportFilePath = path.join(this.reportsDir, `${analysisId}.json`);
    fs.writeFileSync(reportFilePath, JSON.stringify(report, null, 2), 'utf-8');

    return {
      analysisId,
      summary,
      model,
    };
  }

  listReports(): ReportSummaryDto[] {
    const summaries: ReportSummaryDto[] = [];
    for (const analysisId of this.reportsCache.keys()) {
      summaries.push(this.getSummary(analysisId));
    }
    return summaries;
  }
}
