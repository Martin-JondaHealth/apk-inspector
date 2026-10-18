import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: false,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('APK Inspector — Android Static Analysis REST Service')
    .setDescription(
      `
**APK Inspector** is a high-performance backend microservice that reverse-engineers and statically analyzes Android APK packages.

### Features
* **Android Manifest & Internals:** Package metadata, SDK levels, dangerous permissions, exported components without permission guards, and security flags (\`debuggable\`, \`allowBackup\`, \`usesCleartextTraffic\`).
* **Dalvik Bytecode Analysis:** Scans decompiled Smali/DEX strings for hardcoded secrets (AWS keys, Google API keys, JWTs), sensitive URLs, dangerous API calls (\`Runtime.exec\`, \`DexClassLoader\`), and ad/analytics trackers.
* **Native C/C++ Inspection:** Enumerates bundled \`.so\` shared libraries and detects target ABIs (e.g. \`arm64-v8a\`, \`armeabi-v7a\`).
* **OWASP MASVS Mapping:** Translates detected vulnerabilities into structured OWASP Mobile Security Verification Standard findings.
* **AI-Assisted Risk Synthesis:** Synthesizes technical findings into plain-English executive assessments and remediation plans.
      `.trim(),
    )
    .setVersion('1.0.0')
    .addTag('APK Analysis', 'Endpoints for uploading, inspecting, and auditing APKs')
    .addTag('Health', 'Service liveness and engine status')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    customSiteTitle: 'APK Inspector API Docs',
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
    },
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);

  logger.log(`🚀 APK Inspector API is running on http://localhost:${port}`);
  logger.log(`📚 Interactive Swagger API Docs available at http://localhost:${port}/api/docs`);
}

bootstrap();
