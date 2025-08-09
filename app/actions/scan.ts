"use server";

import { performSecurityScan } from "@/lib/security-scanner";

export interface ScanOptions {
  portScan: boolean;
  vulnScan: boolean;
  owaspTop10: boolean;
  gdprCheck: boolean;
  sslAnalysis: boolean;
  headerAnalysis: boolean;
}

export async function scanWebsite(url: string, options?: ScanOptions) {
  try {
    // Validate URL format
    const urlPattern =
      /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$|^(https?:\/\/)?localhost(:\d+)?([/\w .-]*)*\/?$|^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?([/\w .-]*)*\/?$/i;

    if (!urlPattern.test(url.trim())) {
      throw new Error("Invalid URL format. Please enter a valid URL.");
    }

    // Set default options if not provided
    const scanOptions = options || {
      portScan: true,
      vulnScan: true,
      owaspTop10: true,
      gdprCheck: true,
      sslAnalysis: true,
      headerAnalysis: true,
    };

    const results = await performSecurityScan(url.trim(), scanOptions);
    return { success: true, data: results };
  } catch (error) {
    console.error("Scan error:", error);
    return {
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "Unknown scanning error occurred",
    };
  }
}
