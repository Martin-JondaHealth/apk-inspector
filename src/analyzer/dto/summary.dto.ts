import { ApiProperty } from '@nestjs/swagger';

export class SummaryFindingsCountDto {
  @ApiProperty({ example: 1, description: 'Count of critical severity findings' })
  critical: number;

  @ApiProperty({ example: 2, description: 'Count of high severity findings' })
  high: number;

  @ApiProperty({ example: 4, description: 'Count of medium severity findings' })
  medium: number;

  @ApiProperty({ example: 1, description: 'Count of low severity findings' })
  low: number;

  @ApiProperty({ example: 1, description: 'Count of informational findings' })
  info: number;

  @ApiProperty({ example: 9, description: 'Total findings count' })
  total: number;
}

export class ReportSummaryDto {
  @ApiProperty({ example: '2a1bb0fc-4ea3-4d2c-b664-0e57c1b86d88' })
  analysisId: string;

  @ApiProperty({ example: 'com.example.app' })
  package: string;

  @ApiProperty({ example: '1.2.3' })
  versionName: string;

  @ApiProperty({ example: 'sample-test.apk' })
  fileName: string;

  @ApiProperty({ example: 'C', description: 'Overall security grade (A, B, C, D, F)' })
  securityGrade: string;

  @ApiProperty({ type: SummaryFindingsCountDto })
  findingsCount: SummaryFindingsCountDto;

  @ApiProperty({ example: ['Application Is Debuggable', 'Hardcoded Secrets Detected in Bytecode'] })
  topRisks: string[];
}
