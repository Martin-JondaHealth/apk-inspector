import {
  Controller,
  Post,
  Get,
  Param,
  Query,
  UseInterceptors,
  UploadedFile,
  HttpCode,
  HttpStatus,
  ParseUUIDPipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiConsumes,
  ApiBody,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { AnalyzerService } from './analyzer.service';
import { ApkReportDto } from './dto/report.dto';
import { ReportSummaryDto } from './dto/summary.dto';
import { AnalyzeResponseDto, AiSummaryResponseDto } from './dto/analyze-response.dto';

@ApiTags('APK Analysis')
@Controller()
export class AnalyzerController {
  constructor(private readonly analyzerService: AnalyzerService) {}

  @Post('analyze')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Upload and statically analyze an Android APK',
    description:
      'Uploads a multipart .apk file, decompiles and parses AndroidManifest.xml, scans Dalvik bytecode (.dex) for hardcoded secrets, extracts native .so libraries, and evaluates OWASP MASVS security findings.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
          description: 'Android APK package (.apk)',
        },
      },
      required: ['file'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Analysis completed successfully',
    type: AnalyzeResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid file format or missing file' })
  @ApiResponse({ status: 500, description: 'Internal static analysis execution error' })
  @UseInterceptors(
    FileInterceptor('file', {
      limits: {
        fileSize: 100 * 1024 * 1024, // 100 MB max upload
      },
    }),
  )
  async analyze(
    @UploadedFile() file: Express.Multer.File,
  ): Promise<AnalyzeResponseDto> {
    return this.analyzerService.analyzeApk(file);
  }

  @Get('report/:id')
  @ApiOperation({
    summary: 'Get full structured static security report by analysis ID',
    description: 'Retrieves complete JSON report including manifest metadata, security findings, code insights, and native libraries.',
  })
  @ApiParam({ name: 'id', description: 'Analysis UUID returned from /analyze' })
  @ApiResponse({
    status: 200,
    description: 'Full analysis report matching contract',
    type: ApkReportDto,
  })
  @ApiResponse({ status: 404, description: 'Report not found' })
  getReport(@Param('id', ParseUUIDPipe) id: string): ApkReportDto {
    return this.analyzerService.getReport(id);
  }

  @Get('report/:id/summary')
  @ApiOperation({
    summary: 'Get condensed findings and security grade rollup',
    description: 'Returns severity counts (critical, high, medium, low, info), security grade, and top identified risks.',
  })
  @ApiParam({ name: 'id', description: 'Analysis UUID' })
  @ApiResponse({
    status: 200,
    description: 'Condensed report summary',
    type: ReportSummaryDto,
  })
  @ApiResponse({ status: 404, description: 'Report not found' })
  getSummary(@Param('id', ParseUUIDPipe) id: string): ReportSummaryDto {
    return this.analyzerService.getSummary(id);
  }

  @Post('summarize/:id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Generate AI plain-English executive risk summary',
    description:
      'Invokes AI / rule-based heuristics to produce an executive risk report and prioritized remediation plan. Use ?force=true to regenerate.',
  })
  @ApiParam({ name: 'id', description: 'Analysis UUID' })
  @ApiQuery({
    name: 'force',
    required: false,
    type: Boolean,
    description: 'Force re-generation with the LLM instead of serving cached summary',
  })
  @ApiResponse({
    status: 200,
    description: 'AI-generated executive risk assessment',
    type: AiSummaryResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Report not found' })
  async summarize(
    @Param('id', ParseUUIDPipe) id: string,
    @Query('force') force?: string,
  ): Promise<AiSummaryResponseDto> {
    const isForce = force === 'true' || force === '1';
    return this.analyzerService.getAiSummary(id, isForce);
  }

  @Get('reports')
  @ApiOperation({
    summary: 'List all cached APK analysis reports',
    description: 'Returns summaries of all APKs analyzed in the current session or stored on disk.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of report summaries',
    type: [ReportSummaryDto],
  })
  listReports(): ReportSummaryDto[] {
    return this.analyzerService.listReports();
  }
}
