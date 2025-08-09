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

  constructor(timeout = 10) {
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
      // A01: Broken Access Control
      await this.testBrokenAccessControl(url);

      // A02: Cryptographic Failures
      await this.testCryptographicFailures(url);

      // A03: Injection
      await this.testInjectionVulnerabilities(url);

      // A04: Insecure Design
      await this.testInsecureDesign(url);

      // A05: Security Misconfiguration
      await this.testSecurityMisconfiguration(url);

      // A06: Vulnerable and Outdated Components
      await this.testVulnerableComponents(url);

      // A07: Identification and Authentication Failures
      await this.testAuthenticationFailures(url);

      // A08: Software and Data Integrity Failures
      await this.testIntegrityFailures(url);

      // A09: Security Logging and Monitoring Failures
      await this.testLoggingFailures(url);

      // A10: Server-Side Request Forgery (SSRF)
      await this.testSSRFVulnerabilities(url);
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
    const adminPaths = [
      "/admin",
      "/administrator",
      "/admin.php",
      "/wp-admin",
      "/.env",
      "/.git/config",
    ];

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

    // Test for directory traversal
    const traversalPayloads = [
      "../../../../etc/passwd",
      "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ];

    for (const payload of traversalPayloads) {
      const testUrl = `${baseUrl}/${payload}`;
      const response = await this.makeRequest(testUrl);

      if (response && response.status === 200) {
        const text = await response.text();
        if (text.includes("root:") || text.includes("daemon:")) {
          this.vulnerabilities.push({
            id: `A01-${Date.now()}`,
            category: "A01:2021 – Broken Access Control",
            severity: "Critical",
            title: "Directory Traversal Vulnerability",
            description: "Directory traversal attack successful",
            evidence: `Payload: ${payload} returned system files`,
            recommendation:
              "Implement proper input validation and file access controls",
            cwe_id: "CWE-22",
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

    // Test basic SQL injection on URL parameters
    const urlObj = new URL(url);
    if (urlObj.search) {
      const testUrl = url + (url.includes("?") ? "&" : "?") + "test='";
      const testResponse = await this.makeRequest(testUrl);

      if (testResponse) {
        const testHtml = await testResponse.text();
        if (this.detectSQLError(testHtml)) {
          this.vulnerabilities.push({
            id: `A03-${Date.now()}`,
            category: "A03:2021 – Injection",
            severity: "Critical",
            title: "SQL Injection Vulnerability",
            description: "SQL injection detected in URL parameters",
            evidence: "SQL error triggered by injection payload",
            recommendation: "Use parameterized queries and input validation",
            cwe_id: "CWE-89",
          });
        }
      }
    }
  }

  private detectSQLError(responseText: string): boolean {
    const sqlErrors = [
      "sql syntax",
      "mysql_fetch",
      "ora-01756",
      "microsoft ole db",
      "odbc sql server driver",
      "sqlite_master",
      "pg_admin",
      "postgresql",
      "warning: mysql",
      "valid mysql result",
      "mysqlclient",
      "division by zero",
    ];

    return sqlErrors.some((error) =>
      responseText.toLowerCase().includes(error)
    );
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

  private async testVulnerableComponents(url: string): Promise<void> {
    const baseUrl = url.replace(/\/$/, "");
    const vulnerablePaths = [
      "/phpinfo.php",
      "/info.php",
      "/test.php",
      "/phpMyAdmin/",
      "/wp-admin/",
      "/administrator/",
      "/admin/",
      "/elmah.axd",
    ];

    for (const path of vulnerablePaths) {
      const testUrl = baseUrl + path;
      const response = await this.makeRequest(testUrl);

      if (response && response.status === 200) {
        this.vulnerabilities.push({
          id: `A06-${Date.now()}`,
          category: "A06:2021 – Vulnerable and Outdated Components",
          severity: "Medium",
          title: "Potentially Vulnerable Component Detected",
          description: `Accessible component found at ${testUrl}`,
          evidence: `HTTP 200 response from ${path}`,
          recommendation: "Review and update/remove unnecessary components",
          cwe_id: "CWE-1104",
        });
      }
    }

    // Check for outdated JavaScript libraries
    const response = await this.makeRequest(url);
    if (response) {
      const html = await response.text();
      if (html.includes("jquery-1.") || html.includes("jquery/1.")) {
        this.vulnerabilities.push({
          id: `A06-${Date.now()}`,
          category: "A06:2021 – Vulnerable and Outdated Components",
          severity: "Medium",
          title: "Outdated JavaScript Library",
          description: "Potentially outdated jQuery version detected",
          evidence: "Old jQuery version found in HTML",
          recommendation: "Update to latest jQuery version",
          cwe_id: "CWE-1104",
        });
      }
    }
  }

  private async testAuthenticationFailures(url: string): Promise<void> {
    const response = await this.makeRequest(url);
    if (!response) return;

    const html = await response.text();

    // Check for login over HTTP
    if (html.toLowerCase().includes("login") && url.startsWith("http://")) {
      this.vulnerabilities.push({
        id: `A07-${Date.now()}`,
        category: "A07:2021 – Identification and Authentication Failures",
        severity: "High",
        title: "Login Functionality Over Insecure HTTP",
        description: "Login functionality detected over unencrypted HTTP",
        evidence: "Login form found on HTTP page",
        recommendation: "Implement HTTPS for all authentication pages",
        cwe_id: "CWE-319",
      });
    }

    // Check for weak password policies
    if (html.toLowerCase().includes('type="password"')) {
      const passwordRequirements = [
        "minimum",
        "uppercase",
        "lowercase",
        "special character",
        "digit",
        "length",
      ];

      if (
        !passwordRequirements.some((req) => html.toLowerCase().includes(req))
      ) {
        this.vulnerabilities.push({
          id: `A07-${Date.now()}`,
          category: "A07:2021 – Identification and Authentication Failures",
          severity: "Medium",
          title: "Weak Password Policy",
          description: "No visible password complexity requirements",
          evidence: "Password form lacks complexity requirements",
          recommendation: "Implement strong password policy",
          cwe_id: "CWE-521",
        });
      }
    }
  }

  private async testIntegrityFailures(url: string): Promise<void> {
    const response = await this.makeRequest(url);
    if (!response) return;

    const html = await response.text();

    // Check for external resources without integrity checks
    const scriptMatches =
      html.match(/<script[^>]+src=["']https?:\/\/[^"']+["'][^>]*>/gi) || [];
    const linkMatches =
      html.match(/<link[^>]+href=["']https?:\/\/[^"']+["'][^>]*>/gi) || [];

    const externalResourcesWithoutSRI = [];

    for (const script of scriptMatches) {
      if (!script.includes("integrity=")) {
        externalResourcesWithoutSRI.push("script");
      }
    }

    for (const link of linkMatches) {
      if (!link.includes("integrity=")) {
        externalResourcesWithoutSRI.push("stylesheet");
      }
    }

    if (externalResourcesWithoutSRI.length > 0) {
      this.vulnerabilities.push({
        id: `A08-${Date.now()}`,
        category: "A08:2021 – Software and Data Integrity Failures",
        severity: "Medium",
        title: "Missing Subresource Integrity",
        description: "External resources loaded without integrity verification",
        evidence: `${externalResourcesWithoutSRI.length} external resources without SRI`,
        recommendation:
          "Implement Subresource Integrity (SRI) for external resources",
        cwe_id: "CWE-345",
      });
    }
  }

  private async testLoggingFailures(url: string): Promise<void> {
    // Test for lack of rate limiting
    const responses = [];
    for (let i = 0; i < 5; i++) {
      const response = await this.makeRequest(url);
      if (response) {
        responses.push(response.status);
      }
    }

    if (responses.length === 5 && responses.every((status) => status === 200)) {
      this.vulnerabilities.push({
        id: `A09-${Date.now()}`,
        category: "A09:2021 – Security Logging and Monitoring Failures",
        severity: "Low",
        title: "Potential Lack of Rate Limiting",
        description:
          "Multiple rapid requests all succeeded without rate limiting",
        evidence: "5 consecutive requests all returned HTTP 200",
        recommendation: "Implement rate limiting and request monitoring",
        cwe_id: "CWE-770",
      });
    }
  }

  private async testSSRFVulnerabilities(url: string): Promise<void> {
    const urlObj = new URL(url);
    if (!urlObj.search) return;

    const params = new URLSearchParams(urlObj.search);
    const ssrfPayloads = [
      "http://169.254.169.254/",
      "http://127.0.0.1/",
      "http://localhost/",
    ];

    for (const [paramName] of params) {
      for (const payload of ssrfPayloads.slice(0, 2)) {
        const testParams = new URLSearchParams(params);
        testParams.set(paramName, payload);

        const testUrl = `${urlObj.origin}${
          urlObj.pathname
        }?${testParams.toString()}`;
        const response = await this.makeRequest(testUrl);

        if (response && response.status === 200) {
          const text = await response.text();
          if (
            text.includes("root:") ||
            text.includes("daemon:") ||
            text.length > 1000
          ) {
            this.vulnerabilities.push({
              id: `A10-${Date.now()}`,
              category: "A10:2021 – Server-Side Request Forgery (SSRF)",
              severity: "High",
              title: "Potential SSRF Vulnerability",
              description: `SSRF vulnerability detected in parameter '${paramName}'`,
              evidence: `Payload: ${payload} returned suspicious response`,
              recommendation:
                "Implement URL validation and whitelist allowed hosts",
              cwe_id: "CWE-918",
            });
            break;
          }
        }
      }
    }
  }
}
