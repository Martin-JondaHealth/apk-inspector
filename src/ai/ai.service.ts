import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApkReportDto } from '../analyzer/dto/report.dto';

@Injectable()
export class AiService {
  private readonly logger = new Logger(AiService.name);

  constructor(private readonly configService: ConfigService) {}

  async generateRiskSummary(report: ApkReportDto): Promise<{ summary: string; model: string }> {
    const geminiKey = this.configService.get<string>('GEMINI_API_KEY');
    const openAiKey = this.configService.get<string>('OPENAI_API_KEY');

    if (geminiKey) {
      const preferredModel = this.configService.get<string>('GEMINI_MODEL') || 'gemini-2.5-flash';
      try {
        const summary = await this.callGemini(report, geminiKey, preferredModel);
        return { summary, model: preferredModel };
      } catch (err) {
        this.logger.warn(`Gemini API call with ${preferredModel} failed: ${err.message}. Retrying with gemini-flash-latest...`);
        try {
          const summary = await this.callGemini(report, geminiKey, 'gemini-flash-latest');
          return { summary, model: 'gemini-flash-latest' };
        } catch (retryErr) {
          this.logger.warn(`Gemini API retry failed, falling back to local analysis engine: ${retryErr.message}`);
        }
      }
    } else if (openAiKey) {
      try {
        const summary = await this.callOpenAi(report, openAiKey);
        return { summary, model: 'gpt-4o-mini' };
      } catch (err) {
        this.logger.warn(`OpenAI API call failed, falling back to local analysis engine: ${err.message}`);
      }
    }

    // High-quality local heuristic synthesis engine
    const localSummary = this.generateDeterministicSummary(report);
    return { summary: localSummary, model: 'rule-based-security-heuristics' };
  }

  private async callGemini(report: ApkReportDto, apiKey: string, model: string = 'gemini-2.5-flash'): Promise<string> {
    const prompt = this.buildPrompt(report);
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Gemini API responded with status ${res.status}: ${errText}`);
    }

    const data = await res.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || this.generateDeterministicSummary(report);
  }

  private async callOpenAi(report: ApkReportDto, apiKey: string): Promise<string> {
    const prompt = this.buildPrompt(report);
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content: 'You are a veteran Mobile Security Architect and Reverse Engineer auditing Android APKs.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: 0.2,
      }),
    });

    if (!res.ok) {
      throw new Error(`OpenAI API responded with status ${res.status}`);
    }

    const data = await res.json();
    return data.choices?.[0]?.message?.content || this.generateDeterministicSummary(report);
  }

  private buildPrompt(report: ApkReportDto): string {
    return `
You are a Principal Mobile Application Security Engineer conducting an executive technical risk assessment for an Android application.
Provide a clear, authoritative, and actionable security audit report based on this static analysis payload.

Package: ${report.manifest.package} (Version: ${report.manifest.versionName}, MinSDK: ${report.manifest.minSdk}, TargetSDK: ${report.manifest.targetSdk})
File: ${report.apk.fileName} (SHA256: ${report.apk.sha256})
Findings: ${JSON.stringify(report.security.findings, null, 2)}
Hardcoded Secrets: ${JSON.stringify(report.codeInsights.possibleSecrets, null, 2)}
Dangerous APIs: ${JSON.stringify(report.codeInsights.dangerousApiCalls, null, 2)}
Native Libraries: ${JSON.stringify(report.native, null, 2)}

Structure your report into:
1. Executive Risk Summary & Score (Critical/High/Medium/Low)
2. Critical Attack Surfaces (Exported components, bytecode secrets, cleartext traffic)
3. Reverse Engineering & Binary Risk (Smali/JNI native layer)
4. Prioritized Remediation Roadmap
`.trim();
  }

  generateDeterministicSummary(report: ApkReportDto): string {
    const criticalCount = report.security.findings.filter((f) => f.severity === 'critical').length;
    const highCount = report.security.findings.filter((f) => f.severity === 'high').length;
    const mediumCount = report.security.findings.filter((f) => f.severity === 'medium').length;

    let posture = 'POOR (Immediate Action Required)';
    let grade = 'D';
    if (criticalCount === 0 && highCount === 0 && mediumCount === 0) {
      posture = 'STRONG (Compliant with OWASP MASVS)';
      grade = 'A';
    } else if (criticalCount === 0 && highCount === 0) {
      posture = 'MODERATE (Minor Hardening Needed)';
      grade = 'B';
    } else if (criticalCount === 0) {
      posture = 'ELEVATED RISK (Requires Remediation)';
      grade = 'C';
    }

    const totalExported =
      report.manifest.exportedComponents.activities.length +
      report.manifest.exportedComponents.services.length +
      report.manifest.exportedComponents.receivers.length +
      report.manifest.exportedComponents.providers.length;

    return `### 🛡️ APK Inspector Executive Security Audit

**Target Package:** \`${report.manifest.package}\` (v${report.manifest.versionName})  
**Security Posture:** **${posture}** (Grade: **${grade}**)  
**Findings Distribution:** ${criticalCount} Critical | ${highCount} High | ${mediumCount} Medium | ${report.security.findings.length} Total  

---

#### 1. Attack Surface Analysis
- **Manifest Exposure:** Found **${totalExported} exported component(s)**. Components lacking explicit permission guards can be invoked by any malicious application installed on the host device.
- **Network Security:** Cleartext HTTP traffic is **${report.security.usesCleartextTraffic ? 'ENABLED' : 'DISABLED'}**. Hardcoded URLs include ${report.codeInsights.hardcodedUrls.length} endpoints (${report.codeInsights.hardcodedUrls.filter((u) => u.startsWith('http://')).length} unencrypted).
- **Process Debugging:** \`android:debuggable\` is **${report.security.debuggable ? 'TRUE (High Risk: JDWP attached debugger allows memory extraction)' : 'FALSE'}**.
- **Data Backup:** \`android:allowBackup\` is **${report.security.allowBackup ? 'TRUE (Permits adb backup extraction of private sandbox storage)' : 'FALSE'}**.

#### 2. Bytecode & Reverse Engineering Insights
- **Hardcoded Secrets:** ${report.codeInsights.possibleSecrets.length > 0 ? `Detected **${report.codeInsights.possibleSecrets.length} hardcoded credential(s)** in Dalvik bytecode (including ${report.codeInsights.possibleSecrets.map((s) => s.pattern).join(', ')}). Embedded credentials can be extracted in seconds using \`apktool\` or \`jadx\`.` : 'No obvious hardcoded API keys or cryptographic private keys identified.'}
- **Dangerous APIs:** ${report.codeInsights.dangerousApiCalls.length > 0 ? `Identified runtime invocations of: \`${report.codeInsights.dangerousApiCalls.join('`, `')}\`. Dynamic class loading or shell execution can be leveraged for arbitrary code execution.` : 'No critical dynamic classloader or shell execution invocations detected.'}
- **Native C/C++ Layer:** Package bundles **${report.native.libs.length} native shared object(s) (.so)** supporting ABIs: \`${report.native.abis.join(', ') || 'None'}\`. Native JNI code bypasses Java runtime sandboxing and requires memory safety scrutiny.

#### 3. Recommended Remediation Actions
1. **Rotate Exposed Secrets:** Invalidate and rotate any credentials embedded in Dalvik bytecode and move secrets to secure backend vaults.
2. **Harden AndroidManifest:** Disable \`android:debuggable\`, set \`android:allowBackup="false"\`, and enforce \`android:exported="false"\` on internal components.
3. **Enforce Network Security:** Mandate HTTPS for all remote endpoints and configure a strict \`network_security_config.xml\` with domain pinning.
4. **Upgrade SDK Protections:** Ensure \`targetSdkVersion\` is 34+ to benefit from modern Android platform protections.
`;
  }
}
