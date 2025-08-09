export interface GDPRCheckResult {
  url: string
  has_cookie_banner: boolean
  has_privacy_policy: boolean
  has_cookie_policy: boolean
  has_consent_mechanism: boolean
  has_reject_all_option: boolean
  has_granular_consent: boolean
  cookies_found: CookieInfo[]
  privacy_policy_url?: string
  cookie_policy_url?: string
  compliance_score: number
  issues: string[]
  recommendations: string[]
}

export interface CookieInfo {
  name: string
  value: string
  domain?: string
  path?: string
  secure: boolean
  httponly: boolean
  expires?: string
  category: string
}

export class GDPRCookieChecker {
  private timeout: number

  constructor(timeout = 10) {
    this.timeout = timeout
  }

  async checkWebsite(url: string): Promise<GDPRCheckResult> {
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url
    }

    const result: GDPRCheckResult = {
      url,
      has_cookie_banner: false,
      has_privacy_policy: false,
      has_cookie_policy: false,
      has_consent_mechanism: false,
      has_reject_all_option: false,
      has_granular_consent: false,
      cookies_found: [],
      compliance_score: 0,
      issues: [],
      recommendations: [],
    }

    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(this.timeout * 1000),
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
      })

      if (!response.ok) {
        result.issues.push(`Failed to access website: HTTP ${response.status}`)
        return result
      }

      const html = await response.text()

      // Analyze cookies
      result.cookies_found = this.analyzeCookies(response.headers.get("set-cookie") || "")

      // Check for cookie banner
      result.has_cookie_banner = this.checkCookieBanner(html)

      // Check for consent mechanism
      result.has_consent_mechanism = this.checkConsentMechanism(html)

      // Check for reject option
      result.has_reject_all_option = this.checkRejectOption(html)

      // Check for granular consent
      result.has_granular_consent = this.checkGranularConsent(html)

      // Check for privacy policy
      const privacyResult = this.checkPrivacyPolicy(html, url)
      result.has_privacy_policy = privacyResult.found
      result.privacy_policy_url = privacyResult.url

      // Check for cookie policy
      const cookieResult = this.checkCookiePolicy(html, url)
      result.has_cookie_policy = cookieResult.found
      result.cookie_policy_url = cookieResult.url

      // Calculate compliance score
      this.calculateComplianceScore(result)

      // Generate recommendations
      this.generateRecommendations(result)
    } catch (error) {
      result.issues.push(`Error during analysis: ${error instanceof Error ? error.message : "Unknown error"}`)
    }

    return result
  }

  private analyzeCookies(setCookieHeader: string): CookieInfo[] {
    if (!setCookieHeader) return []

    const cookies: CookieInfo[] = []
    const cookieStrings = setCookieHeader.split(",")

    for (const cookieString of cookieStrings) {
      const parts = cookieString.trim().split(";")
      if (parts.length === 0) continue

      const [nameValue] = parts
      const [name, value] = nameValue.split("=")

      if (!name || !value) continue

      const cookie: CookieInfo = {
        name: name.trim(),
        value: value.trim().substring(0, 50) + (value.trim().length > 50 ? "..." : ""),
        secure: parts.some((part) => part.trim().toLowerCase() === "secure"),
        httponly: parts.some((part) => part.trim().toLowerCase() === "httponly"),
        category: this.categorizeCookie(name.trim(), value.trim()),
      }

      // Extract domain, path, expires
      for (const part of parts.slice(1)) {
        const [key, val] = part.trim().split("=")
        if (key.toLowerCase() === "domain") cookie.domain = val
        if (key.toLowerCase() === "path") cookie.path = val
        if (key.toLowerCase() === "expires") cookie.expires = val
      }

      cookies.push(cookie)
    }

    return cookies
  }

  private categorizeCookie(name: string, value: string): string {
    const nameLower = name.toLowerCase()

    // Essential cookies
    const essentialPatterns = ["session", "csrf", "auth", "login", "security"]
    if (essentialPatterns.some((pattern) => nameLower.includes(pattern))) {
      return "essential"
    }

    // Analytics cookies
    const analyticsPatterns = ["_ga", "_gid", "_gat", "analytics", "_utm", "adobe"]
    if (analyticsPatterns.some((pattern) => nameLower.includes(pattern))) {
      return "analytics"
    }

    // Marketing/Advertising cookies
    const marketingPatterns = ["_fb", "facebook", "twitter", "linkedin", "ads", "doubleclick"]
    if (marketingPatterns.some((pattern) => nameLower.includes(pattern))) {
      return "marketing"
    }

    return "functional"
  }

  private checkCookieBanner(html: string): boolean {
    const htmlLower = html.toLowerCase()

    // Check for cookie banner elements
    const cookieBannerSelectors = [
      'class="cookie',
      'id="cookie',
      'class="consent',
      'id="consent',
      'class="privacy',
      'id="privacy',
      'class="gdpr',
      'id="gdpr',
    ]

    if (cookieBannerSelectors.some((selector) => htmlLower.includes(selector))) {
      return true
    }

    // Check for cookie-related text
    const cookiePhrases = [
      "this website uses cookies",
      "we use cookies",
      "accept cookies",
      "cookie consent",
      "privacy preferences",
      "cookie policy",
      "manage cookies",
    ]

    return cookiePhrases.some((phrase) => htmlLower.includes(phrase))
  }

  private checkConsentMechanism(html: string): boolean {
    const htmlLower = html.toLowerCase()

    // Look for accept/consent buttons
    const consentPatterns = [
      ">accept<",
      ">consent<",
      ">agree<",
      ">ok<",
      'value="accept"',
      'value="consent"',
      'value="agree"',
    ]

    return consentPatterns.some((pattern) => htmlLower.includes(pattern))
  }

  private checkRejectOption(html: string): boolean {
    const htmlLower = html.toLowerCase()

    const rejectPatterns = [">reject<", ">decline<", ">deny<", ">refuse<", 'value="reject"', 'value="decline"']

    return rejectPatterns.some((pattern) => htmlLower.includes(pattern))
  }

  private checkGranularConsent(html: string): boolean {
    const htmlLower = html.toLowerCase()

    const granularIndicators = ["analytics", "marketing", "functional", "advertising", "preferences"]

    // Check for checkboxes or toggles with granular options
    const hasCheckboxes = htmlLower.includes('type="checkbox"')
    const hasToggle = htmlLower.includes("toggle") || htmlLower.includes("switch")

    if (hasCheckboxes || hasToggle) {
      return granularIndicators.some((indicator) => htmlLower.includes(indicator))
    }

    return false
  }

  private checkPrivacyPolicy(html: string, baseUrl: string): { found: boolean; url?: string } {
    const htmlLower = html.toLowerCase()

    // Look for privacy policy links
    const privacyPatterns = [/href=["']([^"']*privacy[^"']*)["']/gi, /href=["']([^"']*data.protection[^"']*)["']/gi]

    for (const pattern of privacyPatterns) {
      const matches = htmlLower.match(pattern)
      if (matches && matches.length > 0) {
        const href = matches[0].match(/href=["']([^"']*)["']/)?.[1]
        if (href) {
          const fullUrl = href.startsWith("http") ? href : new URL(href, baseUrl).toString()
          return { found: true, url: fullUrl }
        }
      }
    }

    // Check for privacy policy text
    const privacyTexts = ["privacy policy", "privacy statement", "data protection"]
    const found = privacyTexts.some((text) => htmlLower.includes(text))

    return { found }
  }

  private checkCookiePolicy(html: string, baseUrl: string): { found: boolean; url?: string } {
    const htmlLower = html.toLowerCase()

    // Look for cookie policy links
    const cookiePolicyPattern = /href=["']([^"']*cookie[^"']*policy[^"']*)["']/gi
    const matches = htmlLower.match(cookiePolicyPattern)

    if (matches && matches.length > 0) {
      const href = matches[0].match(/href=["']([^"']*)["']/)?.[1]
      if (href) {
        const fullUrl = href.startsWith("http") ? href : new URL(href, baseUrl).toString()
        return { found: true, url: fullUrl }
      }
    }

    // Check for cookie policy text
    const found = htmlLower.includes("cookie policy") || htmlLower.includes("cookie information")

    return { found }
  }

  private calculateComplianceScore(result: GDPRCheckResult): void {
    let score = 0

    if (result.has_cookie_banner) score += 20
    else result.issues.push("No cookie banner or consent notice found")

    if (result.has_consent_mechanism) score += 20
    else result.issues.push("No clear consent mechanism found")

    if (result.has_reject_all_option) score += 15
    else result.issues.push("No option to reject all cookies found")

    if (result.has_granular_consent) score += 15
    else result.issues.push("No granular cookie preferences found")

    if (result.has_privacy_policy) score += 15
    else result.issues.push("No privacy policy link found")

    if (result.has_cookie_policy) score += 10
    else result.issues.push("No dedicated cookie policy found")

    // Check for non-essential cookies without consent
    if (result.cookies_found.length > 0) {
      const nonEssentialCookies = result.cookies_found.filter((c) => c.category !== "essential")
      if (nonEssentialCookies.length > 0 && !result.has_consent_mechanism) {
        score -= 10
        result.issues.push("Non-essential cookies found without proper consent mechanism")
      } else {
        score += 5
      }
    }

    result.compliance_score = Math.min(Math.max(score, 0), 100)
  }

  private generateRecommendations(result: GDPRCheckResult): void {
    if (!result.has_cookie_banner) {
      result.recommendations.push("Implement a clear cookie consent banner")
    }

    if (!result.has_consent_mechanism) {
      result.recommendations.push("Add proper consent mechanism (Accept/Reject buttons)")
    }

    if (!result.has_reject_all_option) {
      result.recommendations.push("Provide an easy way for users to reject all non-essential cookies")
    }

    if (!result.has_granular_consent) {
      result.recommendations.push("Allow users to choose specific cookie categories")
    }

    if (!result.has_privacy_policy) {
      result.recommendations.push("Create and link to a comprehensive privacy policy")
    }

    if (!result.has_cookie_policy) {
      result.recommendations.push("Create a detailed cookie policy explaining cookie usage")
    }

    // Check for secure cookie settings
    const insecureCookies = result.cookies_found.filter((c) => !c.secure)
    if (insecureCookies.length > 0) {
      result.recommendations.push("Set Secure flag on all cookies containing sensitive data")
    }
  }
}
