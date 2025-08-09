"use client";

import type React from "react";

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
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  AlertTriangle,
  Shield,
  Eye,
  EyeOff,
  ArrowLeft,
  Lock,
  Unlock,
  Bug,
  Info,
  Zap,
} from "lucide-react";
import Link from "next/link";
import Footer from "@/components/footer";

export default function VulnerableLoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loginAttempt, setLoginAttempt] = useState(false);
  const [loginResult, setLoginResult] = useState<string | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<
    string | null
  >(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginAttempt(true);

    // Simulate vulnerable login logic
    setTimeout(() => {
      if (username.includes("'") || password.includes("'")) {
        setLoginResult("sql_injection");
      } else if (username === "admin" && password === "admin") {
        setLoginResult("weak_credentials");
      } else if (username === "" || password === "") {
        setLoginResult("empty_fields");
      } else {
        setLoginResult("invalid_credentials");
      }
      setLoginAttempt(false);
    }, 1000);
  };

  const vulnerabilities = [
    {
      id: "sql_injection",
      title: "SQL Injection",
      severity: "Critical",
      description:
        "The login form is vulnerable to SQL injection attacks. User input is not properly sanitized.",
      example: "Try entering: admin' OR '1'='1' -- as username",
      impact:
        "Attackers can bypass authentication, access unauthorized data, or manipulate the database.",
      remediation:
        "Use parameterized queries, input validation, and prepared statements.",
    },
    {
      id: "weak_credentials",
      title: "Weak Default Credentials",
      severity: "High",
      description:
        "The application uses weak default credentials that are easily guessable.",
      example: "Username: admin, Password: admin",
      impact:
        "Unauthorized access to administrative functions and sensitive data.",
      remediation:
        "Enforce strong password policies and require password changes on first login.",
    },
    {
      id: "no_csrf",
      title: "Missing CSRF Protection",
      severity: "Medium",
      description:
        "The login form lacks CSRF tokens, making it vulnerable to cross-site request forgery.",
      example: "Malicious sites can submit login requests on behalf of users.",
      impact:
        "Attackers can perform unauthorized actions using victim's session.",
      remediation:
        "Implement CSRF tokens and validate them on form submission.",
    },
    {
      id: "no_rate_limiting",
      title: "No Rate Limiting",
      severity: "Medium",
      description:
        "The login endpoint has no rate limiting, allowing brute force attacks.",
      example: "Unlimited login attempts are possible.",
      impact: "Attackers can perform brute force attacks to guess credentials.",
      remediation:
        "Implement rate limiting, account lockouts, and CAPTCHA after failed attempts.",
    },
    {
      id: "password_exposure",
      title: "Password Field Exposure",
      severity: "Low",
      description:
        "Password field can be toggled to plain text, potentially exposing passwords.",
      example: "Click the eye icon to reveal the password.",
      impact: "Shoulder surfing attacks and accidental password exposure.",
      remediation:
        "Consider removing password visibility toggle or add warnings.",
    },
  ];

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

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-red-900 to-gray-900">
      {/* Header */}
      <header className="relative z-10 border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Link href="/">
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-gray-300 hover:text-red-400"
                >
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Back to Home
                </Button>
              </Link>
              <Bug className="h-8 w-8 text-red-400" />
              <h1 className="text-2xl font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent">
                Vulnerable Login Test
              </h1>
            </div>
          </div>
        </div>
      </header>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Warning Banner */}
        <Alert className="mb-8 border-red-500 bg-red-900/20 backdrop-blur-sm">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          <AlertDescription className="text-red-300">
            <strong>Educational Purpose Only:</strong> This is an intentionally
            vulnerable login form designed for security testing and education.
            Do not use this code in production environments.
          </AlertDescription>
        </Alert>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Vulnerable Login Form */}
          <div>
            <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-white">
                  <Unlock className="h-5 w-5 text-red-400" />
                  <span>Vulnerable Login Form</span>
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Test various security vulnerabilities in this intentionally
                  insecure login form
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleLogin} className="space-y-4">
                  <div>
                    <Label htmlFor="username" className="text-gray-300">
                      Username
                    </Label>
                    <Input
                      id="username"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Enter username"
                      className="mt-1 bg-gray-900/50 border-gray-600 text-white placeholder-gray-400"
                    />
                  </div>

                  <div>
                    <Label htmlFor="password" className="text-gray-300">
                      Password
                    </Label>
                    <div className="relative mt-1">
                      <Input
                        id="password"
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter password"
                        className="pr-10 bg-gray-900/50 border-gray-600 text-white placeholder-gray-400"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 text-gray-400 hover:text-white"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>

                  <Button
                    type="submit"
                    className="w-full bg-gradient-to-r from-red-500 to-orange-600 hover:from-red-600 hover:to-orange-700 text-white"
                    disabled={loginAttempt}
                  >
                    {loginAttempt ? (
                      <>
                        <Zap className="h-4 w-4 mr-2 animate-spin" />
                        Logging in...
                      </>
                    ) : (
                      <>
                        <Lock className="h-4 w-4 mr-2" />
                        Login
                      </>
                    )}
                  </Button>
                </form>

                {/* Login Results */}
                {loginResult && (
                  <div className="mt-4">
                    {loginResult === "sql_injection" && (
                      <Alert className="border-red-500 bg-red-900/20">
                        <Bug className="h-4 w-4 text-red-400" />
                        <AlertDescription className="text-red-300">
                          <strong>SQL Injection Detected!</strong> The
                          application is vulnerable to SQL injection. In a real
                          scenario, this could lead to database compromise.
                        </AlertDescription>
                      </Alert>
                    )}

                    {loginResult === "weak_credentials" && (
                      <Alert className="border-orange-500 bg-orange-900/20">
                        <AlertTriangle className="h-4 w-4 text-orange-400" />
                        <AlertDescription className="text-orange-300">
                          <strong>Weak Credentials!</strong> You successfully
                          logged in with default credentials. This represents a
                          serious security risk.
                        </AlertDescription>
                      </Alert>
                    )}

                    {loginResult === "invalid_credentials" && (
                      <Alert className="border-gray-500 bg-gray-900/20">
                        <Info className="h-4 w-4 text-gray-400" />
                        <AlertDescription className="text-gray-300">
                          Invalid credentials. Try testing the vulnerabilities
                          listed on the right.
                        </AlertDescription>
                      </Alert>
                    )}

                    {loginResult === "empty_fields" && (
                      <Alert className="border-blue-500 bg-blue-900/20">
                        <Info className="h-4 w-4 text-blue-400" />
                        <AlertDescription className="text-blue-300">
                          Please fill in both username and password fields.
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Test Scenarios */}
            <Card className="mt-6 bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Test Scenarios</CardTitle>
                <CardDescription className="text-gray-400">
                  Try these inputs to test different vulnerabilities
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="p-3 border border-gray-700 rounded-lg bg-gray-900/30">
                    <h4 className="font-medium text-white">
                      SQL Injection Test
                    </h4>
                    <p className="text-sm text-gray-400 mt-1">
                      Username:{" "}
                      <code className="bg-red-900/30 text-red-300 px-1 rounded">
                        admin' OR '1'='1' --
                      </code>
                    </p>
                    <p className="text-sm text-gray-400">
                      Password:{" "}
                      <code className="bg-gray-700 text-gray-300 px-1 rounded">
                        anything
                      </code>
                    </p>
                  </div>

                  <div className="p-3 border border-gray-700 rounded-lg bg-gray-900/30">
                    <h4 className="font-medium text-white">
                      Default Credentials
                    </h4>
                    <p className="text-sm text-gray-400 mt-1">
                      Username:{" "}
                      <code className="bg-orange-900/30 text-orange-300 px-1 rounded">
                        admin
                      </code>
                    </p>
                    <p className="text-sm text-gray-400">
                      Password:{" "}
                      <code className="bg-orange-900/30 text-orange-300 px-1 rounded">
                        admin
                      </code>
                    </p>
                  </div>

                  <div className="p-3 border border-gray-700 rounded-lg bg-gray-900/30">
                    <h4 className="font-medium text-white">
                      Password Visibility
                    </h4>
                    <p className="text-sm text-gray-400 mt-1">
                      Click the eye icon to toggle password visibility
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Vulnerability Information */}
          <div>
            <Card className="bg-gray-800/50 border-gray-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-white">
                  <Shield className="h-5 w-5 text-cyan-400" />
                  <span>Security Vulnerabilities</span>
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Learn about the security issues present in this login form
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {vulnerabilities.map((vuln) => (
                    <div
                      key={vuln.id}
                      className={`p-3 border border-gray-700 rounded-lg cursor-pointer transition-all duration-200 ${
                        selectedVulnerability === vuln.id
                          ? "border-cyan-500 bg-cyan-900/10"
                          : "hover:bg-gray-900/30"
                      }`}
                      onClick={() =>
                        setSelectedVulnerability(
                          selectedVulnerability === vuln.id ? null : vuln.id
                        )
                      }
                    >
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium text-white">{vuln.title}</h4>
                        <Badge className={getSeverityColor(vuln.severity)}>
                          {vuln.severity}
                        </Badge>
                      </div>

                      {selectedVulnerability === vuln.id && (
                        <div className="mt-3 space-y-2 text-sm animate-in slide-in-from-top-2 duration-200">
                          <div>
                            <strong className="text-gray-300">
                              Description:
                            </strong>
                            <p className="text-gray-400 mt-1">
                              {vuln.description}
                            </p>
                          </div>
                          <div>
                            <strong className="text-gray-300">Example:</strong>
                            <p className="text-gray-400 mt-1">{vuln.example}</p>
                          </div>
                          <div>
                            <strong className="text-gray-300">Impact:</strong>
                            <p className="text-gray-400 mt-1">{vuln.impact}</p>
                          </div>
                          <div>
                            <strong className="text-gray-300">
                              Remediation:
                            </strong>
                            <p className="text-gray-400 mt-1">
                              {vuln.remediation}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
}
