import type { ScanResult } from "./security-scanner";

export function generatePDFContent(
  scanResult: ScanResult,
  targetUrl: string
): string {
  // Generate clean HTML content optimized for PDF conversion
  const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - ${targetUrl}</title>
    <style>
        @page {
            margin: 1in;
            size: A4;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
        }
        
        .header {
            text-align: center;
            border-bottom: 3px solid #0891b2;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .logo {
            color: #0891b2;
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .report-title {
            font-size: 24px;
            color: #1f2937;
            margin: 10px 0;
        }
        
        .target-info {
            font-size: 14px;
            color: #6b7280;
            margin: 5px 0;
        }
        
        .score-container {
            background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
        }
        
        .overall-score {
            font-size: 48px;
            font-weight: bold;
            color: ${
              scanResult.summary.overallScore >= 80
                ? "#10b981"
                : scanResult.summary.overallScore >= 60
                ? "#f59e0b"
                : "#ef4444"
            };
            margin: 10px 0;
        }
        
        .score-label {
            font-size: 16px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 30px 0;
        }
        
        .summary-item {
            text-align: center;
            padding: 20px 10px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            background: #f9fafb;
        }
        
        .summary-count {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .critical { color: #ef4444; }
        .high { color: #f97316; }
        .medium { color: #eab308; }
        .low { color: #3b82f6; }
        .info { color: #6b7280; }
        
        .section {
            margin: 40px 0;
            page-break-inside: avoid;
        }
        
        .section-title {
            font-size: 20px;
            color: #0891b2;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .vulnerability {
            margin: 20px 0;
            padding: 20px;
            border-left: 4px solid;
            background: #f9fafb;
            border-radius: 0 8px 8px 0;
            page-break-inside: avoid;
        }
        
        .vulnerability.critical { border-left-color: #ef4444; }
        .vulnerability.high { border-left-color: #f97316; }
        .vulnerability.medium { border-left-color: #eab308; }
        .vulnerability.low { border-left-color: #3b82f6; }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vuln-title {
            font-size: 18px;
            font-weight: bold;
            color: #1f2937;
            margin: 0;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }
        
        .severity-critical { background-color: #ef4444; }
        .severity-high { background-color: #f97316; }
        .severity-medium { background-color: #eab308; }
        .severity-low { background-color: #3b82f6; }
        
        .vuln-detail {
            margin: 10px 0;
        }
        
        .vuln-label {
            font-weight: bold;
            color: #374151;
            display: inline-block;
            min-width: 120px;
        }
        
        .vuln-text {
            color: #6b7280;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        
        th {
            background-color: #f3f4f6;
            font-weight: bold;
            color: #374151;
        }
        
        .status-open { color: #ef4444; font-weight: bold; }
        .status-closed { color: #10b981; font-weight: bold; }
        
        .gdpr-section {
            background: #f0f9ff;
            border: 1px solid #0891b2;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .gdpr-score {
            font-size: 32px;
            font-weight: bold;
            color: ${
              scanResult.gdpr.score >= 80
                ? "#10b981"
                : scanResult.gdpr.score >= 60
                ? "#f59e0b"
                : "#ef4444"
            };
            text-align: center;
            margin: 20px 0;
        }
        
        .recommendations {
            background: #f0fdf4;
            border: 1px solid #22c55e;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .recommendations ol {
            margin: 0;
            padding-left: 20px;
        }
        
        .recommendations li {
            margin: 10px 0;
            color: #166534;
        }
        
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 12px;
        }
        
        .page-break {
            page-break-before: always;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🛡️ SecureWeb Inspector</div>
        <h1 class="report-title">Security Assessment Report</h1>
        <div class="target-info"><strong>Target:</strong> ${targetUrl}</div>
        <div class="target-info"><strong>Generated:</strong> ${new Date().toLocaleString()}</div>
    </div>

    <div class="score-container">
        <div class="overall-score">${scanResult.summary.overallScore}</div>
        <div class="score-label">Security Score</div>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="summary-count critical">${
                  scanResult.summary.criticalIssues
                }</div>
                <div>Critical</div>
            </div>
            <div class="summary-item">
                <div class="summary-count high">${
                  scanResult.summary.highIssues
                }</div>
                <div>High</div>
            </div>
            <div class="summary-item">
                <div class="summary-count medium">${
                  scanResult.summary.mediumIssues
                }</div>
                <div>Medium</div>
            </div>
            <div class="summary-item">
                <div class="summary-count low">${
                  scanResult.summary.lowIssues
                }</div>
                <div>Low</div>
            </div>
            <div class="summary-item">
                <div class="summary-count info">${
                  scanResult.summary.infoIssues
                }</div>
                <div>Info</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Security Vulnerabilities</h2>
        ${
          scanResult.vulnerabilities.length === 0
            ? '<p style="text-align: center; color: #10b981; font-size: 18px;">✅ No security vulnerabilities found!</p>'
            : scanResult.vulnerabilities
                .map(
                  (vuln) => `
            <div class="vulnerability ${vuln.severity.toLowerCase()}">
                <div class="vuln-header">
                    <h3 class="vuln-title">${vuln.title}</h3>
                    <span class="severity-badge severity-${vuln.severity.toLowerCase()}">${
                    vuln.severity
                  }</span>
                </div>
                <div class="vuln-detail">
                    <span class="vuln-label">Category:</span>
                    <span class="vuln-text">${vuln.category}</span>
                </div>
                <div class="vuln-detail">
                    <span class="vuln-label">Description:</span>
                    <span class="vuln-text">${vuln.description}</span>
                </div>
                <div class="vuln-detail">
                    <span class="vuln-label">Impact:</span>
                    <span class="vuln-text">${vuln.impact}</span>
                </div>
                <div class="vuln-detail">
                    <span class="vuln-label">Remediation:</span>
                    <span class="vuln-text">${vuln.remediation}</span>
                </div>
                ${
                  vuln.cwe
                    ? `
                <div class="vuln-detail">
                    <span class="vuln-label">CWE Reference:</span>
                    <span class="vuln-text">${vuln.cwe}</span>
                </div>
                `
                    : ""
                }
            </div>
        `
                )
                .join("")
        }
    </div>

    <div class="section page-break">
        <h2 class="section-title">OWASP Top 10 Assessment</h2>
        ${scanResult.owaspTop10
          .map(
            (owasp) => `
            <div class="vulnerability ${owasp.risk.toLowerCase()}">
                <div class="vuln-header">
                    <h3 class="vuln-title">${owasp.category}</h3>
                    <span class="severity-badge severity-${owasp.risk.toLowerCase()}">${
              owasp.risk
            }</span>
                </div>
                <div class="vuln-detail">
                    <span class="vuln-label">Description:</span>
                    <span class="vuln-text">${owasp.details}</span>
                </div>
                ${
                  owasp.findings.length > 0
                    ? `
                <div class="vuln-detail">
                    <span class="vuln-label">Findings:</span>
                    <span class="vuln-text">${owasp.findings.join(", ")}</span>
                </div>
                `
                    : ""
                }
            </div>
        `
          )
          .join("")}
    </div>

    <div class="section">
        <h2 class="section-title">Infrastructure Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                ${scanResult.ports
                  .map(
                    (port) => `
                    <tr>
                        <td>${port.port}</td>
                        <td>${port.service}</td>
                        <td>${port.version}</td>
                        <td class="status-${port.status.toLowerCase()}">${
                      port.status
                    }</td>
                    </tr>
                `
                  )
                  .join("")}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">GDPR Compliance Assessment</h2>
        <div class="gdpr-section">
            <div class="gdpr-score">${scanResult.gdpr.score}% Compliant</div>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 20px 0;">
                <div>
                    <strong>Cookie Consent:</strong> ${
                      scanResult.gdpr.cookieConsent
                        ? "✅ Found"
                        : "❌ Not Found"
                    }
                </div>
                <div>
                    <strong>Privacy Policy:</strong> ${
                      scanResult.gdpr.privacyPolicy
                        ? "✅ Found"
                        : "❌ Not Found"
                    }
                </div>
                <div>
                    <strong>Data Processing:</strong> ${
                      scanResult.gdpr.dataProcessingTransparency
                        ? "✅ Found"
                        : "❌ Not Found"
                    }
                </div>
                <div>
                    <strong>User Rights:</strong> ${
                      scanResult.gdpr.userRights ? "✅ Found" : "❌ Not Found"
                    }
                </div>
            </div>
            ${
              scanResult.gdpr.issues.length > 0
                ? `
                <div style="margin-top: 20px;">
                    <strong>Issues Found:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        ${scanResult.gdpr.issues
                          .map(
                            (issue) =>
                              `<li style="margin: 5px 0;">${issue}</li>`
                          )
                          .join("")}
                    </ul>
                </div>
            `
                : ""
            }
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Technical Details</h2>
        <div style="margin: 20px 0;">
            <div class="vuln-detail">
                <span class="vuln-label">Server:</span>
                <span class="vuln-text">${
                  scanResult.technicalDetails.serverInfo
                }</span>
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">Technologies:</span>
                <span class="vuln-text">${
                  scanResult.technicalDetails.technologies.join(", ") ||
                  "None detected"
                }</span>
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">SSL/TLS:</span>
                <span class="vuln-text">${
                  scanResult.technicalDetails.sslInfo.protocol
                } (Grade: ${scanResult.technicalDetails.sslInfo.grade})</span>
            </div>
        </div>
        
        <h3 style="color: #374151; margin: 20px 0 10px 0;">Security Headers</h3>
        <table>
            <thead>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                ${Object.entries(scanResult.technicalDetails.securityHeaders)
                  .map(
                    ([header, value]) => `
                    <tr>
                        <td>${header}</td>
                        <td>${value || "Not Set"}</td>
                        <td style="color: ${value ? "#10b981" : "#ef4444"};">${
                      value ? "✅ Present" : "❌ Missing"
                    }</td>
                    </tr>
                `
                  )
                  .join("")}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Recommendations</h2>
        <div class="recommendations">
            <ol>
                ${
                  scanResult.summary.criticalIssues > 0
                    ? "<li><strong>Critical Priority:</strong> Address all critical vulnerabilities immediately as they pose severe security risks.</li>"
                    : ""
                }
                ${
                  scanResult.summary.highIssues > 0
                    ? "<li><strong>High Priority:</strong> Resolve high-severity issues within 30 days.</li>"
                    : ""
                }
                ${
                  !scanResult.technicalDetails.sslInfo.isSecure
                    ? "<li><strong>Implement HTTPS:</strong> Migrate to HTTPS to protect data in transit.</li>"
                    : ""
                }
                ${
                  !scanResult.technicalDetails.securityHeaders[
                    "Content-Security-Policy"
                  ]
                    ? "<li><strong>Implement CSP:</strong> Add Content Security Policy to prevent XSS attacks.</li>"
                    : ""
                }
                ${
                  scanResult.gdpr.score < 80
                    ? "<li><strong>GDPR Compliance:</strong> Improve GDPR compliance to meet regulatory requirements.</li>"
                    : ""
                }
                <li><strong>Regular Scanning:</strong> Perform security assessments regularly to maintain security posture.</li>
                <li><strong>Security Training:</strong> Ensure development team is trained on secure coding practices.</li>
                <li><strong>Incident Response:</strong> Develop and test incident response procedures.</li>
                <li><strong>Security Monitoring:</strong> Implement continuous security monitoring and logging.</li>
            </ol>
        </div>
    </div>

    <div class="footer">
        <p><strong>SecureWeb Inspector Security Assessment Report</strong></p>
        <p>Generated on ${new Date().toLocaleString()}</p>
        <p>This report was generated for authorized security testing purposes only.</p>
        <p>For questions or support, contact your security team.</p>
    </div>
</body>
</html>
  `;

  return htmlContent;
}
