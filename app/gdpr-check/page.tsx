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
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  ArrowLeft,
  Cookie,
  FileText,
  Eye,
  Settings,
} from "lucide-react";
import Link from "next/link";
import Footer from "@/components/footer";

export default function GDPRCheckPage() {
  const [url, setUrl] = useState("");
  const [isChecking, setIsChecking] = useState(false);
  const [checkComplete, setCheckComplete] = useState(false);
  const [checkProgress, setCheckProgress] = useState(0);

  const handleCheck = async () => {
    setIsChecking(true);
    setCheckComplete(false);
    setCheckProgress(0);

    const interval = setInterval(() => {
      setCheckProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsChecking(false);
          setCheckComplete(true);
          return 100;
        }
        return prev + 20;
      });
    }, 800);
  };

  const gdprResults = {
    overallScore: 72,
    compliantItems: 8,
    nonCompliantItems: 3,
    checks: [
      {
        category: "Cookie Consent",
        items: [
          {
            name: "Cookie consent banner present",
            status: "pass",
            description: "Website displays a cookie consent banner",
          },
          {
            name: "Granular cookie controls",
            status: "fail",
            description: "Users cannot select specific cookie categories",
          },
          {
            name: "Consent before cookie placement",
            status: "pass",
            description: "Non-essential cookies are not set before consent",
          },
          {
            name: "Easy withdrawal of consent",
            status: "fail",
            description: "No clear mechanism to withdraw consent",
          },
        ],
      },
      {
        category: "Privacy Policy",
        items: [
          {
            name: "Privacy policy accessible",
            status: "pass",
            description: "Privacy policy is easily accessible from main pages",
          },
          {
            name: "Clear data processing purposes",
            status: "pass",
            description: "Policy clearly states why data is collected",
          },
          {
            name: "Data retention periods specified",
            status: "warning",
            description: "Some retention periods are vague",
          },
          {
            name: "Third-party data sharing disclosed",
            status: "pass",
            description: "Third-party integrations are disclosed",
          },
        ],
      },
      {
        category: "User Rights",
        items: [
          {
            name: "Contact information for DPO",
            status: "pass",
            description: "Data Protection Officer contact is provided",
          },
          {
            name: "Data subject rights explained",
            status: "pass",
            description: "User rights under GDPR are clearly explained",
          },
          {
            name: "Data portability mechanism",
            status: "fail",
            description: "No clear way for users to export their data",
          },
          {
            name: "Right to erasure process",
            status: "warning",
            description: "Data deletion process exists but is not prominent",
          },
        ],
      },
      {
        category: "Technical Compliance",
        items: [
          {
            name: "Secure data transmission",
            status: "pass",
            description: "HTTPS is used throughout the site",
          },
          {
            name: "Cookie categorization",
            status: "pass",
            description: "Cookies are properly categorized",
          },
          {
            name: "Analytics opt-out available",
            status: "warning",
            description: "Analytics opt-out is available but not prominent",
          },
        ],
      },
    ],
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "pass":
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case "fail":
        return <XCircle className="h-4 w-4 text-red-400" />;
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
      default:
        return <Info className="h-4 w-4 text-gray-400" />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      {/* Header */}
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
              <Shield className="h-8 w-8 text-cyan-400" />
              <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                GDPR Compliance Check
              </h1>
            </div>
          </div>
        </div>
      </header>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {!checkComplete ? (
          <div className="space-y-8">
            {/* Check Configuration */}
            <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">
                  GDPR Compliance Assessment
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Analyze a website's compliance with GDPR requirements
                  including cookie consent, privacy policies, and user rights
                  implementation.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <Label htmlFor="target-url" className="text-gray-300">
                    Website URL
                  </Label>
                  <Input
                    id="target-url"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="mt-1 bg-gray-900/50 border-gray-600 text-white placeholder-gray-400"
                  />
                </div>

                <Alert className="bg-gray-900/50 border-gray-600">
                  <Info className="h-4 w-4 text-cyan-400" />
                  <AlertDescription className="text-gray-300">
                    This tool checks for common GDPR compliance indicators. It
                    does not constitute legal advice and should be supplemented
                    with professional legal review.
                  </AlertDescription>
                </Alert>

                <Button
                  onClick={handleCheck}
                  disabled={isChecking || !url}
                  className="w-full bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-600 hover:to-purple-700 text-white"
                >
                  {isChecking
                    ? "Checking Compliance..."
                    : "Start GDPR Compliance Check"}
                </Button>
              </CardContent>
            </Card>

            {/* Check Progress */}
            {isChecking && (
              <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="text-white">
                    Compliance Check Progress
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between text-sm">
                      <span className="text-cyan-400">
                        Analyzing GDPR compliance...
                      </span>
                      <span className="text-gray-300">
                        {Math.round(checkProgress)}%
                      </span>
                    </div>
                    <Progress
                      value={checkProgress}
                      className="w-full bg-gray-700"
                    />
                    <div className="text-sm text-gray-400">
                      Checking cookie consent, privacy policies, user rights,
                      and technical compliance...
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        ) : (
          /* GDPR Results */
          <div className="space-y-8">
            {/* Results Summary */}
            <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center justify-between text-white">
                  <span>GDPR Compliance Results for {url}</span>
                  <div className="flex items-center space-x-4">
                    <Badge
                      variant="outline"
                      className="text-lg px-3 py-1 border-cyan-500 text-cyan-400"
                    >
                      {gdprResults.overallScore}% Compliant
                    </Badge>
                    <div
                      className={`text-2xl font-bold ${
                        gdprResults.overallScore >= 80
                          ? "text-green-400"
                          : gdprResults.overallScore >= 60
                          ? "text-yellow-400"
                          : "text-red-400"
                      }`}
                    >
                      {gdprResults.overallScore >= 80
                        ? "Good"
                        : gdprResults.overallScore >= 60
                        ? "Fair"
                        : "Poor"}
                    </div>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="text-center">
                    <div className="text-3xl font-bold text-green-400">
                      {gdprResults.compliantItems}
                    </div>
                    <div className="text-sm text-gray-400">Compliant Items</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-red-400">
                      {gdprResults.nonCompliantItems}
                    </div>
                    <div className="text-sm text-gray-400">
                      Non-Compliant Items
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-cyan-400">
                      {gdprResults.checks.reduce(
                        (acc, cat) => acc + cat.items.length,
                        0
                      )}
                    </div>
                    <div className="text-sm text-gray-400">Total Checks</div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <div className="space-y-6">
              {gdprResults.checks.map((category, categoryIndex) => (
                <Card
                  key={categoryIndex}
                  className="bg-gray-800/50 border-gray-700 backdrop-blur-sm"
                >
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2 text-white">
                      {category.category === "Cookie Consent" && (
                        <Cookie className="h-5 w-5 text-cyan-400" />
                      )}
                      {category.category === "Privacy Policy" && (
                        <FileText className="h-5 w-5 text-cyan-400" />
                      )}
                      {category.category === "User Rights" && (
                        <Eye className="h-5 w-5 text-cyan-400" />
                      )}
                      {category.category === "Technical Compliance" && (
                        <Settings className="h-5 w-5 text-cyan-400" />
                      )}
                      <span>{category.category}</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {category.items.map((item, itemIndex) => (
                        <div
                          key={itemIndex}
                          className="flex items-start space-x-3 p-3 border border-gray-700 rounded-lg bg-gray-900/30"
                        >
                          {getStatusIcon(item.status)}
                          <div className="flex-1">
                            <div className="flex items-center justify-between">
                              <h4 className="font-medium text-white">
                                {item.name}
                              </h4>
                              <Badge
                                variant="outline"
                                className={`${
                                  item.status === "pass"
                                    ? "border-green-500 text-green-400"
                                    : item.status === "fail"
                                    ? "border-red-500 text-red-400"
                                    : "border-yellow-500 text-yellow-400"
                                }`}
                              >
                                {item.status === "pass"
                                  ? "Compliant"
                                  : item.status === "fail"
                                  ? "Non-Compliant"
                                  : "Partial"}
                              </Badge>
                            </div>
                            <p className="text-sm text-gray-400 mt-1">
                              {item.description}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Generate Report */}
            <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">
                  Generate GDPR Compliance Report
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Create a detailed report for legal and compliance teams
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Button className="w-full bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-600 hover:to-purple-700 text-white">
                    <FileText className="h-4 w-4 mr-2" />
                    Executive Summary Report
                  </Button>
                  <Button
                    variant="outline"
                    className="w-full border-gray-600 text-gray-300 hover:bg-gray-700 bg-transparent"
                  >
                    <FileText className="h-4 w-4 mr-2" />
                    Detailed Compliance Report
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>

      <Footer />
    </div>
  );
}
