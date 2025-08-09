"use client";

import { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Network,
  Lock,
  ArrowLeft,
  Zap,
  Terminal,
  Download,
} from "lucide-react";
import Link from "next/link";
import Footer from "@/components/footer";
import { scanWebsite } from "@/app/actions/scan";
import { generatePDF } from "@/app/actions/pdf";
import type { ScanResult } from "@/lib/security-scanner";

export default function ScanPage() {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState("");
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [scanOptions, setScanOptions] = useState({
    portScan: true,
    vulnScan: true,
    owaspTop10: true,
    gdprCheck: true,
    sslAnalysis: true,
    headerAnalysis: true,
  });

  const handleScan = async () => {
    if (!url || url.trim() === "") return;

    setIsScanning(true);
    setScanComplete(false);
    setScanProgress(0);
    setScanError(null);
    setScanResults(null);

    // Shorter phases for faster feedback
    const phases = [
      "Initializing scan...",
      "Analyzing target...",
      "Running selected tests...",
      "Processing results...",
      "Generating report...",
    ];

    let phaseIndex = 0;
    const interval = setInterval(() => {
      setScanProgress((prev) => {
        const newProgress = prev + 20;
        if (phaseIndex < phases.length) {
          setCurrentPhase(phases[phaseIndex]);
          phaseIndex++;
        }

        if (newProgress >= 100) {
          clearInterval(interval);
          return 100;
        }
        return newProgress;
      });
    }, 2000); // Slower progress for better UX

    try {
      // Pass scan options to the server action
      const result = await scanWebsite(url.trim(), scanOptions);

      clearInterval(interval);
      setIsScanning(false);
      setScanProgress(100);
      setCurrentPhase("Scan completed!");

      if (result.success && result.data) {
        setScanResults(result.data);
        setScanComplete(true);
      } else {
        setScanError(result.error || "Unknown error occurred");
      }
    } catch (error) {
      clearInterval(interval);
      setIsScanning(false);
      setScanError(error instanceof Error ? error.message : "Scanning failed");
    }
  };

  const handleDownloadPDF = async () => {
    if (!scanResults) return;

    try {
      const result = await generatePDF(scanResults, url);

      if (result.success && result.htmlContent) {
        // Create a proper HTML file that can be converted to PDF
        const blob = new Blob([result.htmlContent], {
          type: "text/html; charset=utf-8",
        });
        const downloadUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = downloadUrl;
        link.download = result.filename || "security-report.html";
        link.style.display = "none";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(downloadUrl);

        // Show instructions for PDF conversion
        alert(
          'HTML report downloaded! To convert to PDF:\n\n1. Open the downloaded HTML file in your browser\n2. Press Ctrl+P (or Cmd+P on Mac)\n3. Select "Save as PDF" as destination\n4. Click Save'
        );
      }
    } catch (error) {
      console.error("PDF download error:", error);
      alert("Failed to generate report. Please try again.");
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-900/50 text-red-300 border-red-500";
      case "high":
        return "bg-orange-900/50 text-orange-300 border-orange-500";
      case "medium":
        return "bg-yellow-900/50 text-yellow-300 border-yellow-500";
      case "low":
        return "bg-blue-900/50 text-blue-300 border-blue-500";
      default:
        return "bg-gray-900/50 text-gray-300 border-gray-500";
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400";
    if (score >= 60) return "text-yellow-400";
    return "text-red-400";
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      <header className="relative z-10 border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Link href="/">
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-gray-300 hover:text-cyan-400"
                >
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Back to Home
                </Button>
              </Link>
              <Terminal className="h-8 w-8 text-cyan-400" />
              <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                Security Scan
              </h1>
            </div>
          </div>
        </div>
      </header>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {!scanComplete ? (
          <div className="space-y-8">
            {/* Scan Configuration */}
            <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white flex items-center space-x-2">
                  <Zap className="h-5 w-5 text-cyan-400" />
                  <span>Scan Configuration</span>
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Configure your security assessment parameters
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <Label htmlFor="target-url" className="text-gray-300">
                    Target URL
                  </Label>
                  <Input
                    id="target-url"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="mt-1 bg-gray-900/50 border-gray-600 text-white placeholder-gray-400"
                  />
                </div>

                <div>
                  <Label className="text-base font-medium text-gray-300">
                    Scan Modules
                  </Label>
                  <div className="grid grid-cols-2 gap-4 mt-3">
                    {Object.entries(scanOptions).map(([key, value]) => (
                      <div key={key} className="flex items-center space-x-2">
                        <Checkbox
                          id={key}
                          checked={value}
                          onCheckedChange={(checked) =>
                            setScanOptions((prev) => ({
                              ...prev,
                              [key]: checked as boolean,
                            }))
                          }
                          className="border-gray-600"
                        />
                        <Label htmlFor={key} className="text-sm text-gray-300">
                          {key === "portScan" && "Port Scanning"}
                          {key === "vulnScan" && "Vulnerability Assessment"}
                          {key === "owaspTop10" && "OWASP Top 10 Testing"}
                          {key === "gdprCheck" && "GDPR Compliance Check"}
                          {key === "sslAnalysis" && "SSL/TLS Analysis"}
                          {key === "headerAnalysis" &&
                            "Security Headers Analysis"}
                        </Label>
                      </div>
                    ))}
                  </div>
                </div>

                <Button
                  onClick={handleScan}
                  disabled={isScanning || !url}
                  className="w-full bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-600 hover:to-purple-700 text-white border-0"
                >
                  {isScanning ? (
                    <>
                      <Terminal className="h-4 w-4 mr-2 animate-pulse" />
                      Scanning in Progress...
                    </>
                  ) : (
                    <>
                      <Zap className="h-4 w-4 mr-2" />
                      Start Comprehensive Scan
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Scan Progress */}
            {isScanning && (
              <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="text-white">Scan Progress</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between text-sm">
                      <span className="text-cyan-400">{currentPhase}</span>
                      <span className="text-gray-300">
                        {Math.round(scanProgress)}%
                      </span>
                    </div>
                    <Progress
                      value={scanProgress}
                      className="w-full bg-gray-700"
                    />
                    <Alert className="bg-gray-900/50 border-gray-600">
                      <Info className="h-4 w-4 text-cyan-400" />
                      <AlertDescription className="text-gray-300">
                        This scan performs real security testing and may take
                        several minutes depending on the target.
                      </AlertDescription>
                    </Alert>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Scan Error */}
            {scanError && (
              <Alert className="bg-red-900/20 border-red-500">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                <AlertDescription className="text-red-300">
                  <strong>Scan Failed:</strong> {scanError}
                </AlertDescription>
              </Alert>
            )}
          </div>
        ) : (
          /* Scan Results */
          <div className="space-y-8">
            {/* Results Summary */}
            <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center justify-between text-white">
                  <span>Scan Results for {url}</span>
                  <div className="flex items-center space-x-4">
                    <Badge
                      variant="outline"
                      className="text-lg px-3 py-1 border-cyan-500 text-cyan-400"
                    >
                      Score: {scanResults?.summary.overallScore}/100
                    </Badge>
                    <Button
                      onClick={handleDownloadPDF}
                      className="bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download PDF Report
                    </Button>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-400">
                      {scanResults?.summary.criticalIssues}
                    </div>
                    <div className="text-sm text-gray-400">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-400">
                      {scanResults?.summary.highIssues}
                    </div>
                    <div className="text-sm text-gray-400">High</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-yellow-400">
                      {scanResults?.summary.mediumIssues}
                    </div>
                    <div className="text-sm text-gray-400">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-400">
                      {scanResults?.summary.lowIssues}
                    </div>
                    <div className="text-sm text-gray-400">Low</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-gray-400">
                      {scanResults?.summary.infoIssues}
                    </div>
                    <div className="text-sm text-gray-400">Info</div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Tabs defaultValue="vulnerabilities" className="w-full">
              <TabsList className="grid w-full grid-cols-4 bg-gray-800/50 border-gray-700">
                <TabsTrigger
                  value="vulnerabilities"
                  className="text-gray-300 data-[state=active]:text-cyan-400"
                >
                  Vulnerabilities
                </TabsTrigger>
                <TabsTrigger
                  value="owasp"
                  className="text-gray-300 data-[state=active]:text-cyan-400"
                >
                  OWASP Top 10
                </TabsTrigger>
                <TabsTrigger
                  value="infrastructure"
                  className="text-gray-300 data-[state=active]:text-cyan-400"
                >
                  Infrastructure
                </TabsTrigger>
                <TabsTrigger
                  value="gdpr"
                  className="text-gray-300 data-[state=active]:text-cyan-400"
                >
                  GDPR Compliance
                </TabsTrigger>
              </TabsList>

              <TabsContent value="vulnerabilities" className="space-y-4">
                {scanResults?.vulnerabilities.filter((vuln) => !vuln.owasp)
                  .length === 0 ? (
                  <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
                    <CardContent className="p-6 text-center">
                      <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-4" />
                      <h3 className="text-lg font-semibold text-white mb-2">
                        No Vulnerabilities Found
                      </h3>
                      <p className="text-gray-400">
                        Great! No security vulnerabilities were detected in this
                        scan.
                      </p>
                    </CardContent>
                  </Card>
                ) : (
                  scanResults?.vulnerabilities
                    .filter((vuln) => !vuln.owasp)
                    .map((vuln) => (
                      <Card
                        key={vuln.id}
                        className="bg-gray-800/50 border-gray-700 backdrop-blur-sm"
                      >
                        <CardHeader>
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-lg text-white">
                              {vuln.title}
                            </CardTitle>
                            <Badge className={getSeverityColor(vuln.severity)}>
                              {vuln.severity}
                            </Badge>
                          </div>
                          <CardDescription className="text-gray-400">
                            {vuln.category}
                          </CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-4">
                            <div>
                              <h4 className="font-medium text-gray-300">
                                Description
                              </h4>
                              <p className="text-gray-400 mt-1">
                                {vuln.description}
                              </p>
                            </div>
                            <div>
                              <h4 className="font-medium text-gray-300">
                                Impact
                              </h4>
                              <p className="text-gray-400 mt-1">
                                {vuln.impact}
                              </p>
                            </div>
                            <div>
                              <h4 className="font-medium text-gray-300">
                                Remediation
                              </h4>
                              <p className="text-gray-400 mt-1">
                                {vuln.remediation}
                              </p>
                            </div>
                            {vuln.cwe && (
                              <div>
                                <h4 className="font-medium text-gray-300">
                                  CWE Reference
                                </h4>
                                <p className="text-gray-400 mt-1">{vuln.cwe}</p>
                              </div>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ))
                )}
              </TabsContent>

              <TabsContent value="owasp" className="space-y-4">
                {scanResults?.owaspTop10.map((owasp, index) => (
                  <Card
                    key={index}
                    className="bg-gray-800/50 border-gray-700 backdrop-blur-sm"
                  >
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-lg text-white">
                          {owasp.category}
                        </CardTitle>
                        <Badge className={getSeverityColor(owasp.risk)}>
                          {owasp.risk}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        <p className="text-gray-400">{owasp.details}</p>
                        {owasp.findings.length > 0 && (
                          <div>
                            <h4 className="font-medium text-gray-300">
                              Findings
                            </h4>
                            <ul className="list-disc list-inside text-gray-400 mt-1">
                              {owasp.findings.map((finding, idx) => (
                                <li key={idx}>{finding}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </TabsContent>

              <TabsContent value="infrastructure" className="space-y-4">
                <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2 text-white">
                      <Network className="h-5 w-5 text-cyan-400" />
                      <span>Open Ports and Services</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {scanResults?.ports.length === 0 ? (
                      <p className="text-gray-400 text-center py-4">
                        No open ports detected
                      </p>
                    ) : (
                      <div className="space-y-3">
                        {scanResults?.ports.map((port, index) => (
                          <div
                            key={index}
                            className="flex items-center justify-between p-3 border border-gray-700 rounded-lg bg-gray-900/30"
                          >
                            <div className="flex items-center space-x-4">
                              <Badge
                                variant="outline"
                                className="border-cyan-500 text-cyan-400"
                              >
                                Port {port.port}
                              </Badge>
                              <div>
                                <p className="font-medium text-white">
                                  {port.service}
                                </p>
                                <p className="text-sm text-gray-400">
                                  {port.version}
                                </p>
                              </div>
                            </div>
                            <Badge
                              variant={
                                port.status === "Open"
                                  ? "destructive"
                                  : "default"
                              }
                              className={
                                port.status === "Open"
                                  ? "bg-red-900/50 text-red-300 border-red-500"
                                  : "bg-gray-700 text-gray-300"
                              }
                            >
                              {port.status}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2 text-white">
                      <Lock className="h-5 w-5 text-cyan-400" />
                      <span>Technical Details</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <h4 className="font-medium text-gray-300">
                          Server Information
                        </h4>
                        <p className="text-gray-400 mt-1">
                          {scanResults?.technicalDetails.serverInfo}
                        </p>
                      </div>
                      <div>
                        <h4 className="font-medium text-gray-300">
                          Technologies Detected
                        </h4>
                        <p className="text-gray-400 mt-1">
                          {scanResults?.technicalDetails.technologies.length ===
                          0
                            ? "None detected"
                            : scanResults?.technicalDetails.technologies.join(
                                ", "
                              )}
                        </p>
                      </div>
                      <div>
                        <h4 className="font-medium text-gray-300">
                          SSL/TLS Information
                        </h4>
                        <p className="text-gray-400 mt-1">
                          Protocol:{" "}
                          {scanResults?.technicalDetails.sslInfo.protocol} |
                          Grade: {scanResults?.technicalDetails.sslInfo.grade}
                        </p>
                      </div>
                      <div>
                        <h4 className="font-medium text-gray-300">
                          Security Headers
                        </h4>
                        <div className="mt-2 space-y-2">
                          {Object.entries(
                            scanResults?.technicalDetails.securityHeaders || {}
                          ).map(([header, value]) => (
                            <div
                              key={header}
                              className="flex items-center justify-between text-sm"
                            >
                              <span className="text-gray-300">{header}</span>
                              <span
                                className={
                                  value ? "text-green-400" : "text-red-400"
                                }
                              >
                                {value ? "✅ Present" : "❌ Missing"}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="gdpr" className="space-y-4">
                <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between text-white">
                      <span className="flex items-center space-x-2">
                        <Shield className="h-5 w-5 text-cyan-400" />
                        <span>GDPR Compliance Assessment</span>
                      </span>
                      <Badge
                        variant="outline"
                        className="text-lg px-3 py-1 border-cyan-500 text-cyan-400"
                      >
                        {scanResults?.gdpr.score}% Compliant
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-6">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="text-center">
                          <div
                            className={`text-2xl ${
                              scanResults?.gdpr.cookieConsent
                                ? "text-green-400"
                                : "text-red-400"
                            }`}
                          >
                            {scanResults?.gdpr.cookieConsent ? "✅" : "❌"}
                          </div>
                          <div className="text-sm text-gray-400">
                            Cookie Consent
                          </div>
                        </div>
                        <div className="text-center">
                          <div
                            className={`text-2xl ${
                              scanResults?.gdpr.privacyPolicy
                                ? "text-green-400"
                                : "text-red-400"
                            }`}
                          >
                            {scanResults?.gdpr.privacyPolicy ? "✅" : "❌"}
                          </div>
                          <div className="text-sm text-gray-400">
                            Privacy Policy
                          </div>
                        </div>
                        <div className="text-center">
                          <div
                            className={`text-2xl ${
                              scanResults?.gdpr.dataProcessingTransparency
                                ? "text-green-400"
                                : "text-red-400"
                            }`}
                          >
                            {scanResults?.gdpr.dataProcessingTransparency
                              ? "✅"
                              : "❌"}
                          </div>
                          <div className="text-sm text-gray-400">
                            Data Transparency
                          </div>
                        </div>
                        <div className="text-center">
                          <div
                            className={`text-2xl ${
                              scanResults?.gdpr.userRights
                                ? "text-green-400"
                                : "text-red-400"
                            }`}
                          >
                            {scanResults?.gdpr.userRights ? "✅" : "❌"}
                          </div>
                          <div className="text-sm text-gray-400">
                            User Rights
                          </div>
                        </div>
                      </div>

                      {scanResults?.gdpr.issues &&
                        scanResults.gdpr.issues.length > 0 && (
                          <div>
                            <h4 className="font-medium text-gray-300 mb-2">
                              Issues Found
                            </h4>
                            <div className="space-y-2">
                              {scanResults.gdpr.issues.map((issue, index) => (
                                <div
                                  key={index}
                                  className="flex items-center space-x-2"
                                >
                                  <XCircle className="h-4 w-4 text-red-400" />
                                  <span className="text-gray-300">{issue}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </div>

      <Footer />
    </div>
  );
}
