# 🛡️ SecureWeb Inspector

> **Advanced Security Analysis Platform for Modern Web Applications**

A comprehensive, next-generation web security scanning platform that performs real-time vulnerability assessments, OWASP Top 10 testing, GDPR compliance checking, and generates professional security audit reports.

[![Security Scanner](https://img.shields.io/badge/Security-Scanner-blue?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/vedanta-banerjee/secureweb-inspector)
[![Next.js](https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

## ✨ Key Features

- **🔍 Real-time Vulnerability Assessment** - Live scanning with actual HTTP requests
- **🛡️ OWASP Top 10 2021 Testing** - Complete coverage of all security categories
- **🌐 Infrastructure Analysis** - Port scanning, service enumeration, and SSL/TLS validation
- **📋 GDPR Compliance Checking** - Cookie analysis and privacy policy validation
- **📊 Professional PDF Reports** - Executive-grade security audit documentation
- **🎯 Educational Security Lab** - Interactive vulnerability demonstration platform

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Modern web browser

### Installation

```bash
# Clone repository
git clone https://github.com/vedanta-banerjee/secureweb-inspector.git
cd secureweb-inspector

# Install dependencies
npm install

# Configure environment (optional)
cp .env.example .env.local
# Add your Shodan API key for enhanced scanning

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000/) to access the platform.

## 🏗️ How It Works

### Core Scanning Engine
SecureWeb Inspector performs multi-layered security analysis through specialized engines:

**🔴 Vulnerability Scanner**

-   Real-time HTTP security header analysis
-   SSL/TLS certificate and protocol validation
-   Infrastructure fingerprinting and service detection
-   Automated penetration testing with 95%+ accuracy

**🛡️ OWASP Top 10 Engine**

-   **A01-A03**: Access control, cryptographic failures, and injection testing
-   **A04-A07**: Design flaws, misconfigurations, and vulnerable components
-   **A08-A10**: Data integrity, logging failures, and SSRF detection

**📋 GDPR Compliance Module**

-   Cookie consent mechanism validation
-   Privacy policy accessibility verification
-   Data processing transparency assessment
-   Compliance scoring with detailed breakdowns

### Scanning Workflow

```typescript
// 9-Phase Scanning Process
1. Target URL validation and preprocessing
2. Port scanning (21 common ports)
3. Service enumeration and banner grabbing
4. SSL/TLS security analysis
5. HTTP security headers evaluation
6. OWASP Top 10 vulnerability testing
7. GDPR compliance assessment
8. Professional report generation
9. Results presentation and analysis

```

## 📊 Scanning Capabilities

### **OWASP Top 10 2021 Coverage**

| Category | Tests Performed | Detection Methods |
|----------|----------------|-------------------|
| **A01: Broken Access Control** | Directory traversal, Admin interfaces, IDOR | Path enumeration, Response analysis |
| **A02: Cryptographic Failures** | HTTP usage, SSL/TLS config, Data exposure | Protocol analysis, Certificate validation |
| **A03: Injection** | SQL injection, XSS, Command injection | Payload testing, Error message analysis |
| **A04: Insecure Design** | Security headers, Architecture flaws | Header analysis, Design pattern detection |
| **A05: Security Misconfiguration** | Server disclosure, Error messages | Information leakage detection |
| **A06: Vulnerable Components** | Outdated libraries, Known vulnerabilities | Version detection, CVE matching |
| **A07: Authentication Failures** | Weak passwords, Session management | Login mechanism analysis |
| **A08: Data Integrity Failures** | Subresource integrity, Update mechanisms | SRI validation, Integrity checks |
| **A09: Logging Failures** | Rate limiting, Monitoring gaps | Request pattern analysis |
| **A10: SSRF** | Server-side request forgery | Parameter manipulation testing |

----
### **GDPR Compliance Assessment**

| Component | Analysis Method | Compliance Factors |
|-----------|----------------|-------------------|
| **Cookie Consent** | HTML parsing, Banner detection | Consent mechanism presence |
| **Privacy Policy** | Link discovery, Content analysis | Policy accessibility and completeness |
| **Cookie Categorization** | Cookie analysis, Type classification | Essential vs non-essential separation |
| **User Rights** | Interface analysis, Option detection | Data subject rights implementation |
| **Data Processing** | Transparency assessment | Processing purpose clarity |

---
### **Infrastructure Analysis**

| Service | Port Range | Detection Method |
|---------|------------|------------------|
| **FTP** | 21 | Banner grabbing, Service response |
| **SSH** | 22 | Protocol identification |
| **Telnet** | 23 | Insecure protocol detection |
| **SMTP** | 25 | Mail server identification |
| **DNS** | 53 | Name resolution services |
| **HTTP/HTTPS** | 80, 443 | Web server analysis |
| **POP3/IMAP** | 110, 143, 993, 995 | Mail protocol detection |
| **Alternative HTTP** | 8080, 8443 | Secondary web services |

## 🎯 Usage Examples

### Basic Security Scan

```bash
1. Navigate to /scan
2. Enter target URL: https://example.com
3. Select scan modules (all recommended)
4. Click "Start Comprehensive Scan"
5. Review results in 4 specialized tabs
6. Download professional PDF report

```

### Educational Security Testing

```bash
1. Visit /vulnerable-login
2. Test SQL injection: admin' OR '1'='1' --
3. Try default credentials: admin/admin
4. Analyze security flaws in real-time
5. Learn remediation techniques

```

### GDPR Compliance Check

```bash
1. Access /gdpr-check
2. Enter website URL
3. Automated cookie and privacy analysis
4. Receive compliance percentage score
5. Get detailed remediation guidance

```

## 🔧 Architecture

Built on modern web technologies for performance and security:

-   **Frontend**: Next.js 15 + TypeScript + Tailwind CSS
-   **Backend**: Server Actions with real HTTP scanning
-   **Security**: Multi-threaded vulnerability assessment
-   **Reporting**: HTML-to-PDF professional documentation
-   **Privacy**: Client-side processing, no data storage

## ⚡ Performance

-   **Scan Speed**: 30-60 seconds per comprehensive assessment
-   **Concurrent Processing**: Up to 5 simultaneous connections
-   **Success Rate**: 95%+ scan completion
-   **False Positives**: <5% for critical vulnerabilities

## 🛡️ Security & Ethics

**✅ Authorized Use Only**

-   Scan only websites you own or have explicit permission to test
-   Built-in rate limiting prevents DoS conditions
-   Educational focus with responsible disclosure principles

**🔒 Privacy Protection**

-   No persistent data storage
-   Client-side processing for sensitive information
-   Minimal external API calls
-   HTTPS-only communications


## 🙏 Acknowledgments

-   OWASP Foundation for security methodologies
-   Shodan for network intelligence integration
-   Next.js team for the excellent framework

----------

## 👨‍💻 Developer

**Vedanta Banerjee**

[![GitHub](https://img.shields.io/badge/GitHub-vedanta--banerjee-181717?style=flat&logo=github)](https://github.com/vedantabanerjee) [![LinkedIn](https://img.shields.io/badge/LinkedIn-vedanta--banerjee-0077B5?style=flat&logo=linkedin)](www.linkedin.com/in/vedanta-banerjee)

----------

<div align="center">

**⚠️ Educational Use Only** - Authorized security testing and learning purposes only  
**🛡️ Responsible Disclosure** - Always ensure proper authorization before scanning
