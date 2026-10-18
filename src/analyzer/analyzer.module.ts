import { Module } from '@nestjs/common';
import { AnalyzerController } from './analyzer.controller';
import { AnalyzerService } from './analyzer.service';
import { AiModule } from '../ai/ai.module';

@Module({
  imports: [AiModule],
  controllers: [AnalyzerController],
  providers: [AnalyzerService],
  exports: [AnalyzerService],
})
export class AnalyzerModule {}
