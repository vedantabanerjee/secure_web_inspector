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
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Scan,
  Bug,
  FileText,
  Zap,
  Eye,
  ArrowRight,
  Terminal,
  Lock,
} from "lucide-react";
import Link from "next/link";
import Footer from "@/components/footer";

export default function HomePage() {
  const [isAnimating, setIsAnimating] = useState(false);

  const features = [
    {
      icon: Scan,
      title: "Vulnerability Scanning",
      description:
        "Comprehensive security analysis including port scanning, OWASP Top 10 testing, and SSL/TLS analysis",
      color: "from-cyan-400 to-blue-500",
    },
    {
      icon: Terminal,
      title: "Real-time Analytics",
      description:
        "Modern dashboard with live results, severity classification, and detailed vulnerability breakdown",
      color: "from-purple-400 to-pink-500",
    },
    {
      icon: FileText,
      title: "PDF Security Reports",
      description:
        "Professional-grade security audit reports with executive summaries and technical details",
      color: "from-green-400 to-emerald-500",
    },
    {
      icon: Bug,
      title: "Vulnerability Testing",
      description:
        "Interactive vulnerable login form to demonstrate common security flaws and attack vectors",
      color: "from-red-400 to-orange-500",
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      {/* Header */}
      <header className="relative z-10 border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Shield className="h-10 w-10 text-cyan-400" />
                <div className="absolute inset-0 h-10 w-10 text-cyan-400 animate-ping opacity-20">
                  <Shield className="h-10 w-10" />
                </div>
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                  SecureWeb Inspector
                </h1>
                <p className="text-gray-400 text-sm">
                  Advanced Security Analysis Platform
                </p>
              </div>
            </div>
            <nav className="flex space-x-6">
              <Link href="/" className="text-cyan-400 font-medium">
                Home
              </Link>
              <Link
                href="/scan"
                className="text-gray-300 hover:text-cyan-400 transition-colors"
              >
                Scan
              </Link>
              <Link
                href="/vulnerable-login"
                className="text-gray-300 hover:text-cyan-400 transition-colors"
              >
                Test Login
              </Link>
            </nav>
          </div>
        </div>
      </header>

      <div className="relative z-10">
        {/* Hero Section */}
        <section className="py-20 px-4 sm:px-6 lg:px-8">
          <div className="max-w-7xl mx-auto text-center">
            <div className="mb-8">
              <Badge className="bg-gradient-to-r from-cyan-500 to-purple-500 text-white border-0 px-4 py-2 text-sm font-medium mb-6">
                <Zap className="h-4 w-4 mr-2" />
                Next-Gen Security Platform
              </Badge>
            </div>

            <h1 className="text-5xl md:text-7xl font-bold mb-6">
              <span className="bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
                Hack-Proof
              </span>
              <br />
              <span className="text-white">Your Web Security</span>
            </h1>

            <p className="text-xl text-gray-300 mb-12 max-w-3xl mx-auto leading-relaxed">
              Unleash the power of advanced vulnerability scanning, real-time
              analytics, and comprehensive security reporting. Built for
              security professionals who demand precision and style.
            </p>

            <div className="flex flex-col sm:flex-row gap-6 justify-center items-center">
              <Link href="/scan" className="inline-block">
                <Button
                  size="lg"
                  className="bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-600 hover:to-purple-700 text-white border-0 px-8 py-4 text-lg font-semibold transform hover:scale-105 transition-all duration-200 shadow-lg hover:shadow-cyan-500/25"
                  onMouseEnter={() => setIsAnimating(true)}
                  onMouseLeave={() => setIsAnimating(false)}
                >
                  <Scan
                    className={`h-5 w-5 mr-2 ${
                      isAnimating ? "animate-spin" : ""
                    }`}
                  />
                  Start Security Scan
                  <ArrowRight className="h-5 w-5 ml-2" />
                </Button>
              </Link>

              <Link href="/vulnerable-login" className="inline-block">
                <Button
                  size="lg"
                  variant="outline"
                  className="border-2 border-red-500 text-red-400 hover:bg-red-500 hover:text-white px-8 py-4 text-lg font-semibold transform hover:scale-105 transition-all duration-200 bg-transparent"
                >
                  <Bug className="h-5 w-5 mr-2" />
                  Test Vulnerabilities
                </Button>
              </Link>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="py-20 px-4 sm:px-6 lg:px-8">
          <div className="max-w-7xl mx-auto">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-white mb-4">
                Cutting-Edge Security Features
              </h2>
              <p className="text-xl text-gray-400 max-w-2xl mx-auto">
                Professional-grade tools designed for modern security challenges
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              {features.map((feature, index) => (
                <Card
                  key={index}
                  className="bg-gray-800/50 border-gray-700 backdrop-blur-sm hover:bg-gray-800/70 transition-all duration-300 group hover:scale-105"
                >
                  <CardHeader>
                    <div className="flex items-center space-x-4">
                      <div
                        className={`p-3 rounded-lg bg-gradient-to-r ${feature.color} group-hover:scale-110 transition-transform duration-200`}
                      >
                        <feature.icon className="h-6 w-6 text-white" />
                      </div>
                      <CardTitle className="text-white text-xl">
                        {feature.title}
                      </CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <CardDescription className="text-gray-300 text-base leading-relaxed">
                      {feature.description}
                    </CardDescription>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-20 px-4 sm:px-6 lg:px-8">
          <div className="max-w-4xl mx-auto">
            <Card className="bg-gradient-to-r from-gray-800 to-gray-900 border-gray-700 overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-purple-500/10"></div>
              <CardContent className="relative p-12 text-center">
                <Lock className="h-16 w-16 text-cyan-400 mx-auto mb-6" />
                <h3 className="text-3xl font-bold text-white mb-4">
                  Ready to Secure Your Web Applications?
                </h3>
                <p className="text-gray-300 text-lg mb-8 max-w-2xl mx-auto">
                  Join thousands of security professionals who trust SecureWeb
                  Inspector for comprehensive vulnerability assessment and
                  reporting.
                </p>
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                  <Link href="/scan" className="inline-block">
                    <Button
                      size="lg"
                      className="bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-600 hover:to-purple-700 text-white border-0 px-8 py-4"
                    >
                      <Scan className="h-5 w-5 mr-2" />
                      Start Your First Scan
                    </Button>
                  </Link>
                  <Link href="/vulnerable-login" className="inline-block">
                    <Button
                      size="lg"
                      variant="outline"
                      className="border-gray-600 text-gray-300 hover:bg-gray-700 px-8 py-4 bg-transparent"
                    >
                      <Eye className="h-5 w-5 mr-2" />
                      Explore Vulnerabilities
                    </Button>
                  </Link>
                </div>
              </CardContent>
            </Card>
          </div>
        </section>
      </div>

      <Footer />
    </div>
  );
}
