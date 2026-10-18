import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  @Get()
  @ApiOperation({ summary: 'Liveness & system health check' })
  @ApiResponse({ status: 200, description: 'Service health status' })
  check() {
    const baseDir = process.cwd();
    const venvPython = path.join(baseDir, '.venv', 'bin', 'python');
    const pythonExe = fs.existsSync(venvPython) ? venvPython : 'python3';

    let engineReady = false;
    let androguardReady = false;
    try {
      execSync(`${pythonExe} -c "import androguard; print('ok')"`, { stdio: 'pipe', timeout: 5000 });
      engineReady = true;
      androguardReady = true;
    } catch {
      try {
        execSync(`${pythonExe} --version`, { stdio: 'pipe', timeout: 5000 });
        engineReady = true;
      } catch {
        engineReady = false;
      }
    }

    return {
      status: 'ok',
      service: 'apk-inspector',
      timestamp: new Date().toISOString(),
      uptimeSeconds: process.uptime(),
      environment: {
        nodeVersion: process.version,
        pythonExecutable: pythonExe,
        engineReady,
        androguardReady,
      },
    };
  }
}
