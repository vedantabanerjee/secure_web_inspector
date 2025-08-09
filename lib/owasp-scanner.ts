export interface OwaspVulnerability {
  id: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
  cwe_id?: string;
  cvss_score?: number;
}

export interface OwaspScanResult {
  target_url: string;
  scan_time: string;
  vulnerabilities: OwaspVulnerability[];
  total_requests: number;
  scan_duration: number;
}

export class OWASPTop10Scanner {
  private session: any;
  private timeout: number;
  private vulnerabilities: OwaspVulnerability[];
  private request_count: number;

  constructor(timeout = 5) {
    // Reduced default timeout for Vercel
    this.timeout = timeout;
    this.vulnerabilities = [];
    this.request_count = 0;
  }

  private async makeRequest(
    url: string,
    method = "GET",
    data?: any,
    headers?: Record<string, string>
  ): Promise<Response | null> {
    try {
      this.request_count++;
      const options: RequestInit = {
        method,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          ...headers,
        },
        signal: AbortSignal.timeout(this.timeout * 1000),
      };

      if (data && method === "POST") {
        options.body = data instanceof FormData ? data : JSON.stringify(data);
        if (!(data instanceof FormData)) {
          options.headers = {
            ...options.headers,
            "Content-Type": "application/json",
          };
        }
      }

      const response = await fetch(url, options);
      return response;
    } catch (error) {
      return null;
    }
  }

  async scanWebsite(url: string): Promise<OwaspScanResult> {
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
    }

    const startTime = Date.now();
    this.vulnerabilities = [];
    this.request_count = 0;

    try {
      // Reduced test scope for Vercel performance
      // A01: Broken Access Control (limited tests)
      await this.testBrokenAccessControl(url);

      // A02: Cryptographic Failures
      await this.testCryptographicFailures(url);

      // A03: Injection (basic tests only)
      await this.testInjectionVulnerabilities(url);

      // A04: Insecure Design
      await this.testInsecureDesign(url);

      // A05: Security Misconfiguration
      await this.testSecurityMisconfiguration(url);

      // Skip heavy tests for Vercel (A06-A10) to avoid timeout
    } catch (error) {
      console.error("OWASP scanning error:", error);
    }

    return {
      target_url: url,
      scan_time: new Date().toISOString(),
      vulnerabilities: this.vulnerabilities,
      total_requests: this.request_count,
      scan_duration: (Date.now() - startTime) / 1000,
    };
  }

  private async testBrokenAccessControl(url: string): Promise<void> {
    const baseUrl = url.replace(/\/$/, "");
    // Reduced path list for faster scanning
    const adminPaths = ["/admin", "/.env", "/.git/config"];

    for (const path of adminPaths) {
      const testUrl = baseUrl + path;
      const response = await this.makeRequest(testUrl);

      if (response && response.status === 200) {
        const text = await response.text();
        if (
          text.toLowerCase().includes("admin") ||
          text.toLowerCase().includes("dashboard") ||
          text.toLowerCase().includes("control panel")
        ) {
          this.vulnerabilities.push({
            id: `A01-${Date.now()}`,
            category: "A01:2021 – Broken Access Control",
            severity: "High",
            title: "Exposed Administrative Interface",
            description: `Administrative interface accessible at ${testUrl}`,
            evidence: `HTTP 200 response with admin-related content`,
            recommendation:
              "Implement proper access controls and authentication",
            cwe_id: "CWE-284",
          });
        }
      }
    }
  }

  private async testCryptographicFailures(url: string): Promise<void> {
    // Check if HTTP is used instead of HTTPS
    if (url.startsWith("http://")) {
      this.vulnerabilities.push({
        id: `A02-${Date.now()}`,
        category: "A02:2021 – Cryptographic Failures",
        severity: "Critical",
        title: "Unencrypted Communication",
        description: "Website uses HTTP instead of HTTPS",
        evidence: `URL scheme is HTTP: ${url}`,
        recommendation: "Implement HTTPS with valid SSL/TLS certificate",
        cwe_id: "CWE-319",
      });
    }

    // Test for sensitive data in URLs
    const response = await this.makeRequest(url);
    if (response) {
      const responseUrl = response.url;
      const sensitivePatterns = [
        /password=[\w]+/i,
        /token=[a-zA-Z0-9]+/i,
        /key=[a-zA-Z0-9]+/i,
        /api_key=[a-zA-Z0-9]+/i,
      ];

      for (const pattern of sensitivePatterns) {
        if (pattern.test(responseUrl)) {
          this.vulnerabilities.push({
            id: `A02-${Date.now()}`,
            category: "A02:2021 – Cryptographic Failures",
            severity: "Medium",
            title: "Sensitive Data in URL",
            description: "Sensitive information found in URL parameters",
            evidence: `Pattern found in URL: ${responseUrl}`,
            recommendation: "Never include sensitive data in URLs",
            cwe_id: "CWE-598",
          });
        }
      }
    }
  }

  private async testInjectionVulnerabilities(url: string): Promise<void> {
    const response = await this.makeRequest(url);
    if (!response) return;

    const html = await response.text();

    // Test for SQL injection error messages
    const sqlErrors = [
      "sql syntax",
      "mysql_fetch",
      "ora-01756",
      "microsoft ole db",
      "odbc sql server driver",
      "sqlite_master",
      "postgresql",
    ];

    for (const error of sqlErrors) {
      if (html.toLowerCase().includes(error)) {
        this.vulnerabilities.push({
          id: `A03-${Date.now()}`,
          category: "A03:2021 – Injection",
          severity: "High",
          title: "SQL Error Message Disclosure",
          description: "Database error messages exposed in response",
          evidence: `SQL error pattern found: ${error}`,
          recommendation:
            "Implement proper error handling and use parameterized queries",
          cwe_id: "CWE-89",
        });
      }
    }

    // Test for XSS vulnerability indicators
    if (
      html.includes("<script>") &&
      !response.headers.get("content-security-policy")
    ) {
      this.vulnerabilities.push({
        id: `A03-${Date.now()}`,
        category: "A03:2021 – Injection",
        severity: "High",
        title: "Potential XSS Vulnerability",
        description: "Script tags found without CSP protection",
        evidence: "Script tags present with no Content Security Policy",
        recommendation:
          "Implement Content Security Policy and input validation",
        cwe_id: "CWE-79",
      });
    }
  }

  private async testInsecureDesign(url: string): Promise<void> {
    const response = await this.makeRequest(url);
    if (!response) return;

    const securityHeaders = {
      "X-Frame-Options": "Clickjacking protection missing",
      "X-Content-Type-Options": "MIME type sniffing protection missing",
      "X-XSS-Protection": "XSS protection header missing",
      "Strict-Transport-Security": "HSTS header missing",
      "Content-Security-Policy": "CSP header missing",
    };

    for (const [header, description] of Object.entries(securityHeaders)) {
      if (!response.headers.get(header.toLowerCase())) {
        const severity = [
          "Content-Security-Policy",
          "X-Frame-Options",
        ].includes(header)
          ? "High"
          : "Medium";
        this.vulnerabilities.push({
          id: `A04-${Date.now()}`,
          category: "A04:2021 – Insecure Design",
          severity: severity as "High" | "Medium",
          title: `Missing Security Header: ${header}`,
          description: description,
          evidence: `Header '${header}' not found in response`,
          recommendation: `Implement ${header} header`,
          cwe_id: "CWE-693",
        });
      }
    }
  }

  private async testSecurityMisconfiguration(url: string): Promise<void> {
    const response = await this.makeRequest(url);
    if (!response) return;

    // Check for server information disclosure
    const serverHeader = response.headers.get("server");
    if (serverHeader && /apache\/|nginx\/|iis\//i.test(serverHeader)) {
      const versionMatch = serverHeader.match(/[\d.]+/);
      if (versionMatch) {
        this.vulnerabilities.push({
          id: `A05-${Date.now()}`,
          category: "A05:2021 – Security Misconfiguration",
          severity: "Low",
          title: "Server Version Disclosure",
          description: `Server version information disclosed: ${serverHeader}`,
          evidence: `Server header: ${serverHeader}`,
          recommendation: "Hide server version information",
          cwe_id: "CWE-200",
        });
      }
    }

    // Check for verbose error messages
    if (response.status >= 400) {
      const html = await response.text();
      const errorIndicators = [
        "stack trace",
        "exception",
        "error occurred",
        "debug",
        "warning:",
        "notice:",
        "fatal error",
        "mysql error",
      ];

      if (
        errorIndicators.some((indicator) =>
          html.toLowerCase().includes(indicator)
        )
      ) {
        this.vulnerabilities.push({
          id: `A05-${Date.now()}`,
          category: "A05:2021 – Security Misconfiguration",
          severity: "Medium",
          title: "Verbose Error Messages",
          description: "Application reveals detailed error information",
          evidence: "Error page contains debug information",
          recommendation:
            "Implement custom error pages without sensitive information",
          cwe_id: "CWE-209",
        });
      }
    }
  }
}
