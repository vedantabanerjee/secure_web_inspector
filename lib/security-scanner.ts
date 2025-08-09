import { OWASPTop10Scanner } from "./owasp-scanner"
import { GDPRCookieChecker } from "./gdpr-checker"

// Shodan API integration
const SHODAN_API_KEY = "NN0RjrCVFKzsBRa1qpd13OkX0bM1YOqg"

export interface ScanResult {
  summary: {
    overallScore: number
    criticalIssues: number
    highIssues: number
    mediumIssues: number
    lowIssues: number
    infoIssues: number
  }
  vulnerabilities: Vulnerability[]
  ports: PortInfo[]
  gdpr: GDPRResult
  owaspTop10: OwaspResult[]
  technicalDetails: TechnicalDetails
}

export interface Vulnerability {
  id: number
  title: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  category: string
  description: string
  impact: string
  remediation: string
  evidence?: string
  cwe?: string
}

export interface PortInfo {
  port: number
  service: string
  version: string
  status: "Open" | "Closed" | "Filtered"
  banner?: string
}

export interface GDPRResult {
  score: number
  issues: string[]
  cookieConsent: boolean
  privacyPolicy: boolean
  dataProcessingTransparency: boolean
  userRights: boolean
}

export interface OwaspResult {
  category: string
  risk: "Critical" | "High" | "Medium" | "Low"
  findings: string[]
  details: string
}

export interface TechnicalDetails {
  serverInfo: string
  technologies: string[]
  sslInfo: any
  securityHeaders: Record<string, string | null>
  cookies: any[]
}

// Utility function to extract domain from URL
function extractDomain(url: string): string {
  try {
    let processedUrl = url
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      processedUrl = "https://" + url
    }
    const urlObj = new URL(processedUrl)
    return urlObj.hostname
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0]
  }
}

// Port scanning function
async function scanPorts(domain: string): Promise<PortInfo[]> {
  const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
  const results: PortInfo[] = []

  for (const port of commonPorts) {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 3000)

      const response = await fetch(`http://${domain}:${port}`, {
        method: "HEAD",
        signal: controller.signal,
        mode: "no-cors",
      }).catch(() => null)

      clearTimeout(timeoutId)

      if (response || port === 80 || port === 443) {
        let service = "Unknown"
        const version = "Unknown"

        switch (port) {
          case 21:
            service = "FTP"
            break
          case 22:
            service = "SSH"
            break
          case 23:
            service = "Telnet"
            break
          case 25:
            service = "SMTP"
            break
          case 53:
            service = "DNS"
            break
          case 80:
            service = "HTTP"
            break
          case 110:
            service = "POP3"
            break
          case 143:
            service = "IMAP"
            break
          case 443:
            service = "HTTPS"
            break
          case 993:
            service = "IMAPS"
            break
          case 995:
            service = "POP3S"
            break
          case 8080:
            service = "HTTP-Alt"
            break
          case 8443:
            service = "HTTPS-Alt"
            break
        }

        results.push({
          port,
          service,
          version,
          status: "Open",
        })
      }
    } catch (error) {
      // Port is likely closed or filtered
    }
  }

  return results
}

// HTTP security headers analysis
async function analyzeSecurityHeaders(url: string): Promise<Record<string, string | null>> {
  try {
    const response = await fetch(url, { method: "HEAD" })
    const headers = response.headers

    return {
      "X-Frame-Options": headers.get("x-frame-options"),
      "X-Content-Type-Options": headers.get("x-content-type-options"),
      "X-XSS-Protection": headers.get("x-xss-protection"),
      "Strict-Transport-Security": headers.get("strict-transport-security"),
      "Content-Security-Policy": headers.get("content-security-policy"),
      "Referrer-Policy": headers.get("referrer-policy"),
      "Permissions-Policy": headers.get("permissions-policy"),
      Server: headers.get("server"),
    }
  } catch (error) {
    return {}
  }
}

// SSL/TLS analysis
async function analyzeSSL(url: string): Promise<any> {
  try {
    const response = await fetch(url)
    const isHttps = url.startsWith("https://")

    return {
      isSecure: isHttps,
      protocol: isHttps ? "HTTPS" : "HTTP",
      certificate: isHttps ? "Valid" : "None",
      grade: isHttps ? "A" : "F",
    }
  } catch (error) {
    return {
      isSecure: false,
      protocol: "Unknown",
      certificate: "Error",
      grade: "F",
    }
  }
}

// Technology detection
async function detectTechnologies(url: string): Promise<string[]> {
  try {
    const response = await fetch(url)
    const html = await response.text()
    const headers = response.headers

    const technologies: string[] = []

    // Server detection
    const server = headers.get("server")
    if (server) {
      technologies.push(`Server: ${server}`)
    }

    // Framework detection
    if (html.includes("wp-content") || html.includes("wordpress")) {
      technologies.push("WordPress")
    }
    if (html.includes("drupal")) {
      technologies.push("Drupal")
    }
    if (html.includes("joomla")) {
      technologies.push("Joomla")
    }
    if (html.includes("react")) {
      technologies.push("React")
    }
    if (html.includes("angular")) {
      technologies.push("Angular")
    }
    if (html.includes("vue")) {
      technologies.push("Vue.js")
    }

    // JavaScript libraries
    if (html.includes("jquery")) {
      technologies.push("jQuery")
    }
    if (html.includes("bootstrap")) {
      technologies.push("Bootstrap")
    }

    return technologies
  } catch (error) {
    return []
  }
}

// OWASP Top 10 testing using manual scanner
async function performOwaspTop10Tests(url: string, domain: string): Promise<OwaspResult[]> {
  const scanner = new OWASPTop10Scanner()
  const scanResult = await scanner.scanWebsite(url)

  // Group vulnerabilities by category
  const categoryMap = new Map<string, OwaspResult>()

  for (const vuln of scanResult.vulnerabilities) {
    if (!categoryMap.has(vuln.category)) {
      categoryMap.set(vuln.category, {
        category: vuln.category,
        risk: vuln.severity,
        findings: [],
        details: vuln.description,
      })
    }

    const existing = categoryMap.get(vuln.category)!
    existing.findings.push(vuln.evidence)

    // Use highest severity
    if (
      vuln.severity === "Critical" ||
      (vuln.severity === "High" && existing.risk !== "Critical") ||
      (vuln.severity === "Medium" && !["Critical", "High"].includes(existing.risk))
    ) {
      existing.risk = vuln.severity
    }
  }

  return Array.from(categoryMap.values())
}

// GDPR compliance checking using manual checker
async function checkGDPRCompliance(url: string): Promise<GDPRResult> {
  const checker = new GDPRCookieChecker()
  const result = await checker.checkWebsite(url)

  return {
    score: result.compliance_score,
    issues: result.issues,
    cookieConsent: result.has_consent_mechanism,
    privacyPolicy: result.has_privacy_policy,
    dataProcessingTransparency: result.has_cookie_policy,
    userRights: result.has_granular_consent,
  }
}

// Shodan integration for additional intelligence
async function getShodanIntelligence(domain: string): Promise<any> {
  try {
    const response = await fetch(`https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=${domain}`)
    if (response.ok) {
      const data = await response.json()
      return data
    }
  } catch (error) {
    console.error("Shodan API error:", error)
  }
  return null
}

// Main scanning function
export async function performSecurityScan(url: string): Promise<ScanResult> {
  const domain = extractDomain(url)
  let processedUrl = url

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    processedUrl = "https://" + url
  }

  try {
    // Perform all scans in parallel for better performance
    const [ports, securityHeaders, sslInfo, technologies, owaspResults, gdprResult, shodanData] = await Promise.all([
      scanPorts(domain),
      analyzeSecurityHeaders(processedUrl),
      analyzeSSL(processedUrl),
      detectTechnologies(processedUrl),
      performOwaspTop10Tests(processedUrl, domain),
      checkGDPRCompliance(processedUrl),
      getShodanIntelligence(domain),
    ])

    // Generate vulnerabilities based on findings (excluding OWASP findings)
    const vulnerabilities: Vulnerability[] = []
    let vulnId = 1

    // SSL/TLS vulnerabilities
    if (!sslInfo.isSecure) {
      vulnerabilities.push({
        id: vulnId++,
        title: "Insecure HTTP Protocol",
        severity: "Critical",
        category: "Cryptographic Failures",
        description: "The website is not using HTTPS, transmitting data in plain text.",
        impact: "All data transmitted can be intercepted and read by attackers",
        remediation: "Implement SSL/TLS certificate and redirect all HTTP traffic to HTTPS",
        cwe: "CWE-319",
      })
    }

    // Security headers vulnerabilities
    if (!securityHeaders["X-Frame-Options"]) {
      vulnerabilities.push({
        id: vulnId++,
        title: "Missing X-Frame-Options Header",
        severity: "Medium",
        category: "Security Misconfiguration",
        description: "The X-Frame-Options header is not set, making the site vulnerable to clickjacking attacks.",
        impact: "Attackers can embed the site in malicious frames to trick users",
        remediation: "Set X-Frame-Options header to DENY or SAMEORIGIN",
        cwe: "CWE-1021",
      })
    }

    if (!securityHeaders["Content-Security-Policy"]) {
      vulnerabilities.push({
        id: vulnId++,
        title: "Missing Content Security Policy",
        severity: "Medium",
        category: "Injection",
        description: "No Content Security Policy header found, increasing XSS risk.",
        impact: "Higher risk of cross-site scripting attacks",
        remediation: "Implement a strict Content Security Policy",
        cwe: "CWE-79",
      })
    }

    if (!securityHeaders["Strict-Transport-Security"] && sslInfo.isSecure) {
      vulnerabilities.push({
        id: vulnId++,
        title: "Missing HSTS Header",
        severity: "Medium",
        category: "Cryptographic Failures",
        description: "HTTP Strict Transport Security header is missing.",
        impact: "Users may be vulnerable to protocol downgrade attacks",
        remediation: "Implement HSTS header with appropriate max-age",
        cwe: "CWE-319",
      })
    }

    // DO NOT add OWASP findings to vulnerabilities array - they have their own section

    // Calculate overall score
    const criticalCount = vulnerabilities.filter((v) => v.severity === "Critical").length
    const highCount = vulnerabilities.filter((v) => v.severity === "High").length
    const mediumCount = vulnerabilities.filter((v) => v.severity === "Medium").length
    const lowCount = vulnerabilities.filter((v) => v.severity === "Low").length

    let overallScore = 100
    overallScore -= criticalCount * 25
    overallScore -= highCount * 15
    overallScore -= mediumCount * 10
    overallScore -= lowCount * 5
    overallScore = Math.max(overallScore, 0)

    return {
      summary: {
        overallScore,
        criticalIssues: criticalCount,
        highIssues: highCount,
        mediumIssues: mediumCount,
        lowIssues: lowCount,
        infoIssues: 0,
      },
      vulnerabilities,
      ports,
      gdpr: gdprResult,
      owaspTop10: owaspResults,
      technicalDetails: {
        serverInfo: securityHeaders["Server"] || "Unknown",
        technologies,
        sslInfo,
        securityHeaders,
        cookies: [], // Would need more complex analysis
      },
    }
  } catch (error) {
    console.error("Scanning error:", error)
    throw new Error(`Scanning failed: ${error instanceof Error ? error.message : "Unknown error"}`)
  }
}
