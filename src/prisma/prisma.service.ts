import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);
  public isConnected = false;

  constructor(private readonly configService: ConfigService) {
    super();
  }

  async onModuleInit() {
    const dbUrl = this.configService.get<string>('DATABASE_URL');
    if (!dbUrl || dbUrl.trim() === '') {
      this.logger.log('No DATABASE_URL configured. Operating in filesystem storage mode.');
      this.isConnected = false;
      return;
    }

    try {
      await this.$connect();
      this.isConnected = true;
      this.logger.log('✅ Successfully connected to PostgreSQL database.');
    } catch (err) {
      this.isConnected = false;
      this.logger.warn(`Could not connect to PostgreSQL (${err.message}). Falling back to local filesystem store.`);
    }
  }

  async onModuleDestroy() {
    if (this.isConnected) {
      await this.$disconnect();
    }
  }
}
