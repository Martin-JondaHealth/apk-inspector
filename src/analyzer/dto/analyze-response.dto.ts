import { ApiProperty } from '@nestjs/swagger';

export class AnalyzeResponseDto {
  @ApiProperty({ example: '2a1bb0fc-4ea3-4d2c-b664-0e57c1b86d88', description: 'Unique analysis tracking ID' })
  analysisId: string;

  @ApiProperty({ example: 'completed', enum: ['completed', 'processing', 'failed'] })
  status: string;

  @ApiProperty({ example: 'APK static analysis completed successfully' })
  message: string;

  @ApiProperty({ example: '/report/2a1bb0fc-4ea3-4d2c-b664-0e57c1b86d88' })
  reportUrl: string;
}

export class AiSummaryResponseDto {
  @ApiProperty({ example: '2a1bb0fc-4ea3-4d2c-b664-0e57c1b86d88' })
  analysisId: string;

  @ApiProperty({ example: 'Executive Security Assessment: The APK demonstrates critical security posture deficiencies...' })
  summary: string;

  @ApiProperty({ example: 'gemini-1.5-flash / automated-security-heuristics' })
  model: string;
}
