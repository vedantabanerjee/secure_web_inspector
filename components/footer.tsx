import { Shield, Github, Twitter, Linkedin, Mail } from "lucide-react";
import Link from "next/link";

export default function Footer() {
  return (
    <footer className="bg-gray-900 border-t border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center space-x-3 mb-4">
              <Shield className="h-8 w-8 text-cyan-400" />
              <span className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                SecureWeb Inspector
              </span>
            </div>
            <p className="text-gray-400 max-w-md">Developer: Vedanta Banerjee</p>
            <p className="text-gray-400 mb-6 max-w-md">Version: 0.0.7</p>
            <div className="flex space-x-4">
              <a
                href="https://github.com/vedantabanerjee/secure_web_inspector"
                className="text-gray-400 hover:text-cyan-400 transition-colors"
              >
                <Github className="h-5 w-5" />
              </a>
              <a
                href="https://x.com/0xr1sh1"
                className="text-gray-400 hover:text-cyan-400 transition-colors"
              >
                <Twitter className="h-5 w-5" />
              </a>
              <a
                href="https://www.linkedin.com/in/vedanta-banerjee"
                className="text-gray-400 hover:text-cyan-400 transition-colors"
              >
                <Linkedin className="h-5 w-5" />
              </a>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-white font-semibold mb-4">Quick Links</h3>
            <ul className="space-y-2">
              <li>
                <Link
                  href="/"
                  className="text-gray-400 hover:text-cyan-400 transition-colors"
                >
                  Home
                </Link>
              </li>
              <li>
                <Link
                  href="/scan"
                  className="text-gray-400 hover:text-cyan-400 transition-colors"
                >
                  Security Scan
                </Link>
              </li>
              <li>
                <Link
                  href="/vulnerable-login"
                  className="text-gray-400 hover:text-cyan-400 transition-colors"
                >
                  Test Login
                </Link>
              </li>
            </ul>
          </div>
        </div>

        <div className="border-t border-gray-800 mt-8 pt-8 flex flex-col md:flex-row justify-between items-center">
          <p className="text-gray-400 text-sm">
            © 2025 SecureWeb Inspector. All rights reserved by Vedanta Banerjee.
          </p>
          <p className="text-gray-400 text-sm mt-2 md:mt-0">
            For authorized security testing only.
          </p>
        </div>
      </div>
    </footer>
  );
}
