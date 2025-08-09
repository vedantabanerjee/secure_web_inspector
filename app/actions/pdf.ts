"use server"

import { generatePDFContent } from "@/lib/pdf-generator"
import type { ScanResult } from "@/lib/security-scanner"

export async function generatePDF(scanResult: ScanResult, targetUrl: string) {
  try {
    const htmlContent = generatePDFContent(scanResult, targetUrl)

    // Return the HTML content with proper headers for PDF conversion
    return {
      success: true,
      htmlContent,
      filename: `security-report-${new Date().toISOString().split("T")[0]}.html`,
      contentType: "text/html; charset=utf-8",
    }
  } catch (error) {
    console.error("PDF generation error:", error)
    return {
      success: false,
      error: "Failed to generate PDF report",
    }
  }
}
