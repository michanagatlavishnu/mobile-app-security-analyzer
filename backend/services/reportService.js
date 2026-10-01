const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const Permission = require('../models/Permission');
const Component = require('../models/Component');
const NetworkFinding = require('../models/NetworkFinding');
const Secret = require('../models/Secret');

class ReportService {
  /**
   * Fetches all scan data atomically for reporting
   */
  static async getFullScanReportData(scanId, userId, isAdmin = false) {
    const scan = await Scan.findByIdForUser(scanId, userId, isAdmin);
    if (!scan) {
      throw new Error('Scan record not found or access denied');
    }

    const [vulnerabilities, permissions, components, networkFindings, secrets] = await Promise.all([
      Vulnerability.findByScanId(scanId),
      Permission.findByScanId(scanId),
      Component.findByScanId(scanId),
      NetworkFinding.findByScanId(scanId),
      Secret.findByScanId(scanId),
    ]);

    return {
      scan,
      vulnerabilities,
      permissions,
      components,
      networkFindings,
      secrets,
    };
  }

  /**
   * Generates a clean, professional PDF security assessment report stream using PDFKit
   */
  static generatePdfReport(reportData, outputStream) {
    const { scan, vulnerabilities, permissions, components, networkFindings, secrets } = reportData;

    const doc = new PDFDocument({
      margin: 40,
      size: 'A4',
      info: {
        Title: `Security Assessment Report - ${scan.package_name || scan.original_filename}`,
        Author: 'Mobile App Security Analyzer',
        Subject: 'Android Application Static Security Audit',
      },
    });

    doc.pipe(outputStream);

    // Helpers
    const brandColor = '#06b6d4'; // Cyan
    const darkBg = '#0f172a'; // Slate 900
    const textLight = '#f8fafc'; // Slate 50
    const textMuted = '#94a3b8'; // Slate 400
    const redColor = '#ef4444';
    const orangeColor = '#f97316';
    const yellowColor = '#eab308';
    const greenColor = '#10b981';

    const getSevColor = (sev) => {
      switch ((sev || '').toUpperCase()) {
        case 'CRITICAL': return redColor;
        case 'HIGH': return orangeColor;
        case 'MEDIUM': return yellowColor;
        case 'LOW': return brandColor;
        default: return textMuted;
      }
    };

    // ==========================================
    // PAGE 1: COVER PAGE
    // ==========================================
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(darkBg);

    // Decorative top cyber bar
    doc.rect(0, 0, doc.page.width, 10).fill(brandColor);

    doc.moveDown(4);
    doc.fillColor(brandColor).fontSize(14).font('Helvetica-Bold').text('MOBILE APP SECURITY ANALYZER', 50, 80, { characterSpacing: 2 });
    doc.fillColor(textMuted).fontSize(10).font('Helvetica').text('ADVANCED ANDROID STATIC SECURITY ASSESSMENT PLATFORM', 50, 100);

    doc.moveDown(4);
    doc.fillColor(textLight).fontSize(28).font('Helvetica-Bold').text('SECURITY AUDIT REPORT', 50, 170);
    doc.fillColor(brandColor).fontSize(14).font('Helvetica-Bold').text('Comprehensive Automated Vulnerability & Threat Assessment', 50, 205);

    // Target application box
    doc.rect(50, 250, doc.page.width - 100, 130).fillAndStroke('#1e293b', '#334155');

    doc.fillColor(textMuted).fontSize(9).font('Helvetica-Bold').text('TARGET APPLICATION', 70, 270);
    doc.fillColor(textLight).fontSize(14).font('Helvetica-Bold').text(scan.package_name || scan.original_filename, 70, 285);

    doc.fillColor(textMuted).fontSize(9).font('Helvetica').text('ORIGINAL ARCHIVE:', 70, 315);
    doc.fillColor(textLight).fontSize(9).font('Helvetica-Bold').text(scan.original_filename, 180, 315);

    doc.fillColor(textMuted).fontSize(9).font('Helvetica').text('APPLICATION VERSION:', 70, 332);
    doc.fillColor(textLight).fontSize(9).font('Helvetica-Bold').text(`${scan.version_name || '1.0'} (Build ${scan.version_code || 1})`, 180, 332);

    doc.fillColor(textMuted).fontSize(9).font('Helvetica').text('AUDIT RECORD ID:', 70, 349);
    doc.fillColor(textLight).fontSize(9).font('Helvetica-Bold').text(`#${scan.id}`, 180, 349);

    // Score & Risk summary card
    const scoreBoxY = 410;
    doc.rect(50, scoreBoxY, doc.page.width - 100, 120).fillAndStroke('#1e293b', '#334155');

    doc.fillColor(textMuted).fontSize(10).font('Helvetica-Bold').text('OVERALL SECURITY SCORE', 70, scoreBoxY + 25);
    doc.fillColor(getSevColor(scan.risk_level)).fontSize(46).font('Helvetica-Bold').text(`${scan.security_score ?? 'N/A'}`, 70, scoreBoxY + 45);
    doc.fillColor(textMuted).fontSize(16).font('Helvetica').text('/ 100', 140, scoreBoxY + 68);

    doc.fillColor(textMuted).fontSize(10).font('Helvetica-Bold').text('COMPUTED RISK TIER', 320, scoreBoxY + 25);
    doc.fillColor(getSevColor(scan.risk_level)).fontSize(22).font('Helvetica-Bold').text(`${scan.risk_level || 'UNKNOWN'}`, 320, scoreBoxY + 50);
    doc.fillColor(textMuted).fontSize(8).font('Helvetica').text('DETERMINISTIC SEVERITY-WEIGHTED RATING', 320, scoreBoxY + 80);

    // Metadata footer
    const footerY = doc.page.height - 100;
    doc.fillColor(textMuted).fontSize(8).font('Helvetica')
      .text(`Generated: ${new Date().toISOString()}  |  SHA-256: ${scan.sha256?.substring(0, 32)}...`, 50, footerY);
    doc.text('Assessment Methodology: Pure Static Binary & Bytecode Inspection (Non-Execution)', 50, footerY + 14);
    doc.fillColor(brandColor).text('Confidential Document • Internal Security Review Use Only', 50, footerY + 28);

    // ==========================================
    // PAGE 2: EXECUTIVE SUMMARY & PROFILE
    // ==========================================
    doc.addPage();
    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#ffffff');

    // Page Header
    doc.fillColor('#0f172a').fontSize(18).font('Helvetica-Bold').text('1. Executive Summary', 40, 40);
    doc.rect(40, 62, doc.page.width - 80, 2).fill(brandColor);

    doc.fillColor('#334155').fontSize(9.5).font('Helvetica').text(
      'This document provides the security audit findings for the specified Android application archive. The static analysis suite audited application manifest configurations, Dalvik executable string pools, exposed IPC components, cryptographic algorithms, hardcoded credentials, and network communications.',
      40, 75, { width: doc.page.width - 80, lineGap: 3 }
    );

    // Metrics Grid
    const critCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const medCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const lowCount = vulnerabilities.filter(v => v.severity === 'LOW').length;

    const summaryBoxY = 135;
    const colW = (doc.page.width - 80 - 30) / 4;

    const drawStatCard = (x, label, count, color) => {
      doc.rect(x, summaryBoxY, colW, 55).fillAndStroke('#f8fafc', '#e2e8f0');
      doc.rect(x, summaryBoxY, colW, 4).fill(color);
      doc.fillColor(color).fontSize(20).font('Helvetica-Bold').text(`${count}`, x + 10, summaryBoxY + 12);
      doc.fillColor('#64748b').fontSize(8).font('Helvetica-Bold').text(label, x + 10, summaryBoxY + 38);
    };

    drawStatCard(40, 'CRITICAL RISKS', critCount, redColor);
    drawStatCard(40 + colW + 10, 'HIGH RISKS', highCount, orangeColor);
    drawStatCard(40 + (colW + 10) * 2, 'MEDIUM RISKS', medCount, yellowColor);
    drawStatCard(40 + (colW + 10) * 3, 'LOW RISKS', lowCount, brandColor);

    // Application Profile Table
    doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('2. Application Profile & Telemetry', 40, 215);
    doc.rect(40, 233, doc.page.width - 80, 1).fill('#cbd5e1');

    const profileData = [
      ['Package Identifier', scan.package_name || 'N/A'],
      ['Version Name & Code', `${scan.version_name || '1.0'} (VersionCode: ${scan.version_code || 1})`],
      ['Archive Filename', scan.original_filename],
      ['SHA-256 Checksum', scan.sha256],
      ['Archive File Size', `${(scan.file_size / (1024 * 1024)).toFixed(2)} MB (${scan.file_size} bytes)`],
      ['Declared Permissions', `${permissions.length} total permissions`],
      ['Registered Components', `${components.length} components (${components.filter(c => c.exported).length} exported)`],
      ['Exposed Secrets Detected', `${secrets.length} hardcoded credential signature(s)`],
      ['Network Findings Discovered', `${networkFindings.length} endpoint/config finding(s)`],
    ];

    let currentY = 245;
    profileData.forEach(([key, val], idx) => {
      const bg = idx % 2 === 0 ? '#f8fafc' : '#ffffff';
      doc.rect(40, currentY, doc.page.width - 80, 18).fill(bg);
      doc.fillColor('#475569').fontSize(8.5).font('Helvetica-Bold').text(key, 50, currentY + 4);
      doc.fillColor('#0f172a').fontSize(8).font('Helvetica').text(String(val), 210, currentY + 4, { width: 330, ellipsis: true });
      currentY += 18;
    });

    // Severity Breakdown Section
    currentY += 20;
    doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('3. Risk Breakdown Table', 40, currentY);
    currentY += 18;
    doc.rect(40, currentY, doc.page.width - 80, 1).fill('#cbd5e1');
    currentY += 10;

    const breakdownHeaders = ['Severity Tier', 'Finding Count', 'Risk Impact Description'];
    doc.rect(40, currentY, doc.page.width - 80, 18).fill('#0f172a');
    doc.fillColor('#ffffff').fontSize(8).font('Helvetica-Bold')
      .text(breakdownHeaders[0], 50, currentY + 5)
      .text(breakdownHeaders[1], 150, currentY + 5)
      .text(breakdownHeaders[2], 240, currentY + 5);
    currentY += 18;

    const bRows = [
      ['CRITICAL', critCount, 'Immediate exploitation potential (e.g. command injection, AWS root credentials, unauthenticated exported services)'],
      ['HIGH', highCount, 'Severe vulnerabilities (e.g. hardcoded API keys, debuggable build, cleartext HTTP communication, DCL)'],
      ['MEDIUM', medCount, 'Moderate risk misconfigurations (e.g. outdated target SDK, weak cipher modes, user CA trust)'],
      ['LOW', lowCount, 'Minor security hygiene concerns (e.g. allowBackup enabled without sensitive flags)'],
    ];

    bRows.forEach(([sev, cnt, desc], i) => {
      const bg = i % 2 === 0 ? '#f8fafc' : '#ffffff';
      doc.rect(40, currentY, doc.page.width - 80, 24).fill(bg);
      doc.fillColor(getSevColor(sev)).fontSize(8.5).font('Helvetica-Bold').text(sev, 50, currentY + 7);
      doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text(String(cnt), 160, currentY + 7);
      doc.fillColor('#475569').fontSize(7.5).font('Helvetica').text(desc, 240, currentY + 4, { width: 280 });
      currentY += 24;
    });

    // ==========================================
    // PAGE 3: DETAILED VULNERABILITY FINDINGS
    // ==========================================
    doc.addPage();
    doc.fillColor('#0f172a').fontSize(18).font('Helvetica-Bold').text('4. Detailed Security Vulnerabilities', 40, 40);
    doc.rect(40, 62, doc.page.width - 80, 2).fill(brandColor);

    currentY = 75;

    if (vulnerabilities.length === 0) {
      doc.fillColor('#10b981').fontSize(11).font('Helvetica').text('No security vulnerabilities were identified during static inspection.', 40, currentY);
    } else {
      vulnerabilities.forEach((f, idx) => {
        // Check page overflow
        if (currentY > doc.page.height - 160) {
          doc.addPage();
          currentY = 40;
        }

        const sevCol = getSevColor(f.severity);

        // Header strip
        doc.rect(40, currentY, doc.page.width - 80, 22).fillAndStroke('#f1f5f9', '#cbd5e1');
        doc.rect(40, currentY, 6, 22).fill(sevCol);

        doc.fillColor(sevCol).fontSize(8.5).font('Helvetica-Bold').text(`[${f.severity}]`, 52, currentY + 6);
        doc.fillColor('#0f172a').fontSize(9.5).font('Helvetica-Bold').text(`${idx + 1}. ${f.title}`, 120, currentY + 6, { width: 380, ellipsis: true });

        currentY += 26;

        // Meta tags
        doc.fillColor('#64748b').fontSize(8).font('Helvetica')
          .text(`Category: ${f.category}  |  CWE: ${f.cwe || 'N/A'}  |  OWASP: ${f.owasp_category || 'N/A'}  |  Confidence: ${f.confidence || 'HIGH'}`, 48, currentY);
        currentY += 14;

        // Description
        doc.fillColor('#334155').fontSize(8.5).font('Helvetica').text(f.description, 48, currentY, { width: doc.page.width - 96, lineGap: 2 });
        currentY += doc.heightOfString(f.description, { width: doc.page.width - 96 }) + 6;

        // Observed Evidence (Masked!)
        if (f.evidence) {
          doc.rect(48, currentY, doc.page.width - 96, 18).fill('#0f172a');
          doc.fillColor('#38bdf8').fontSize(7.5).font('Courier').text(f.evidence, 54, currentY + 4, { width: doc.page.width - 108, ellipsis: true });
          currentY += 22;
        }

        // Recommendation
        if (f.recommendation) {
          doc.fillColor('#0284c7').fontSize(7.5).font('Helvetica-Bold').text('Remediation: ', 48, currentY, { continued: true });
          doc.fillColor('#475569').font('Helvetica').text(f.recommendation, { width: doc.page.width - 96 });
          currentY += doc.heightOfString(f.recommendation, { width: doc.page.width - 96 }) + 10;
        } else {
          currentY += 10;
        }
      });
    }

    // ==========================================
    // PAGE 4: SECRETS & NETWORK INTELLIGENCE
    // ==========================================
    doc.addPage();
    doc.fillColor('#0f172a').fontSize(18).font('Helvetica-Bold').text('5. Hardcoded Secrets & Network Intelligence', 40, 40);
    doc.rect(40, 62, doc.page.width - 80, 2).fill(brandColor);

    currentY = 75;

    doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text('Hardcoded Secrets Discovered (Strictly Masked)', 40, currentY);
    currentY += 18;

    if (secrets.length === 0) {
      doc.fillColor('#64748b').fontSize(8.5).font('Helvetica').text('No hardcoded credentials, API keys, or tokens identified.', 40, currentY);
      currentY += 20;
    } else {
      // Table Header
      doc.rect(40, currentY, doc.page.width - 80, 16).fill('#0f172a');
      doc.fillColor('#ffffff').fontSize(7.5).font('Helvetica-Bold')
        .text('Secret Type', 48, currentY + 4)
        .text('Severity', 160, currentY + 4)
        .text('Location', 220, currentY + 4)
        .text('Masked Credential Evidence', 320, currentY + 4);
      currentY += 16;

      secrets.forEach((s, i) => {
        const bg = i % 2 === 0 ? '#f8fafc' : '#ffffff';
        doc.rect(40, currentY, doc.page.width - 80, 18).fill(bg);
        doc.fillColor('#0f172a').fontSize(8).font('Helvetica-Bold').text(s.secret_type, 48, currentY + 4);
        doc.fillColor(getSevColor(s.severity)).fontSize(7.5).font('Helvetica-Bold').text(s.severity, 160, currentY + 4);
        doc.fillColor('#64748b').fontSize(7.5).font('Helvetica').text(s.location || 'classes.dex', 220, currentY + 4);
        doc.fillColor('#d97706').fontSize(7.5).font('Courier').text(s.masked_value, 320, currentY + 4);
        currentY += 18;
      });
      currentY += 15;
    }

    // Network Findings
    doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text('Network Intelligence & Cleartext Endpoints', 40, currentY);
    currentY += 18;

    if (networkFindings.length === 0) {
      doc.fillColor('#64748b').fontSize(8.5).font('Helvetica').text('No insecure network communications or configurations detected.', 40, currentY);
      currentY += 20;
    } else {
      doc.rect(40, currentY, doc.page.width - 80, 16).fill('#0f172a');
      doc.fillColor('#ffffff').fontSize(7.5).font('Helvetica-Bold')
        .text('Issue Classification', 48, currentY + 4)
        .text('Severity', 180, currentY + 4)
        .text('Telemetry & Evidence', 250, currentY + 4);
      currentY += 16;

      networkFindings.forEach((n, i) => {
        if (currentY > doc.page.height - 80) {
          doc.addPage();
          currentY = 40;
        }
        const bg = i % 2 === 0 ? '#f8fafc' : '#ffffff';
        doc.rect(40, currentY, doc.page.width - 80, 22).fill(bg);
        doc.fillColor('#0f172a').fontSize(8).font('Helvetica-Bold').text(n.type, 48, currentY + 4, { width: 125 });
        doc.fillColor(getSevColor(n.severity)).fontSize(7.5).font('Helvetica-Bold').text(n.severity, 180, currentY + 4);
        doc.fillColor('#475569').fontSize(7).font('Courier').text(n.evidence || n.description, 250, currentY + 4, { width: 260, ellipsis: true });
        currentY += 22;
      });
    }

    // ==========================================
    // PAGE 5: PERMISSIONS, COMPONENTS & FOOTER
    // ==========================================
    doc.addPage();
    doc.fillColor('#0f172a').fontSize(18).font('Helvetica-Bold').text('6. Permissions & Component Analysis', 40, 40);
    doc.rect(40, 62, doc.page.width - 80, 2).fill(brandColor);

    currentY = 75;
    doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text('Declared Permissions', 40, currentY);
    currentY += 18;

    // Permissions summary
    doc.rect(40, currentY, doc.page.width - 80, 16).fill('#0f172a');
    doc.fillColor('#ffffff').fontSize(7.5).font('Helvetica-Bold')
      .text('Permission Identifier', 48, currentY + 4)
      .text('Risk Rating', 280, currentY + 4)
      .text('Protection Level', 380, currentY + 4);
    currentY += 16;

    permissions.slice(0, 15).forEach((p, i) => {
      const bg = i % 2 === 0 ? '#f8fafc' : '#ffffff';
      doc.rect(40, currentY, doc.page.width - 80, 16).fill(bg);
      doc.fillColor('#0f172a').fontSize(7.5).font('Courier').text(p.permission_name, 48, currentY + 3);
      doc.fillColor(getSevColor(p.danger_level)).fontSize(7.5).font('Helvetica-Bold').text(p.danger_level, 280, currentY + 3);
      doc.fillColor('#64748b').fontSize(7.5).font('Helvetica').text(p.danger_level === 'CRITICAL' ? 'dangerous' : 'normal', 380, currentY + 3);
      currentY += 16;
    });

    if (permissions.length > 15) {
      doc.fillColor('#64748b').fontSize(7.5).font('Helvetica').text(`... and ${permissions.length - 15} additional permissions`, 48, currentY + 4);
      currentY += 16;
    }

    currentY += 15;
    doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text('Components Audited', 40, currentY);
    currentY += 18;

    doc.rect(40, currentY, doc.page.width - 80, 16).fill('#0f172a');
    doc.fillColor('#ffffff').fontSize(7.5).font('Helvetica-Bold')
      .text('Type', 48, currentY + 4)
      .text('Component Name', 120, currentY + 4)
      .text('Exported', 380, currentY + 4)
      .text('Permission Constraint', 440, currentY + 4);
    currentY += 16;

    components.slice(0, 12).forEach((c, i) => {
      const bg = i % 2 === 0 ? '#f8fafc' : '#ffffff';
      doc.rect(40, currentY, doc.page.width - 80, 16).fill(bg);
      doc.fillColor('#0284c7').fontSize(7.5).font('Helvetica-Bold').text(c.component_type.toUpperCase(), 48, currentY + 3);
      doc.fillColor('#0f172a').fontSize(7.5).font('Courier').text(c.component_name, 120, currentY + 3, { width: 250, ellipsis: true });
      doc.fillColor(c.exported ? redColor : '#64748b').fontSize(7.5).font('Helvetica-Bold').text(c.exported ? 'YES (TRUE)' : 'NO', 380, currentY + 3);
      doc.fillColor('#64748b').fontSize(7).font('Helvetica').text(c.permission || 'None', 440, currentY + 3);
      currentY += 16;
    });

    // Final Report Footer
    const endFooterY = doc.page.height - 60;
    doc.rect(40, endFooterY, doc.page.width - 80, 1).fill('#cbd5e1');
    doc.fillColor('#64748b').fontSize(8).font('Helvetica')
      .text('Generated by Mobile App Security Analyzer  •  Static analysis only  •  No application execution performed', 40, endFooterY + 10, { align: 'center' });

    doc.end();
  }

  /**
   * Generates sanitized structured JSON export
   */
  static generateJsonReport(reportData) {
    const { scan, vulnerabilities, permissions, components, networkFindings, secrets } = reportData;

    return {
      reportType: 'Mobile App Security Analyzer - Static Assessment',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      disclaimer: 'Static analysis only. No application execution performed. All secrets masked.',
      application: {
        id: scan.apk_id,
        filename: scan.original_filename,
        packageName: scan.package_name || 'N/A',
        versionName: scan.version_name || '1.0',
        versionCode: scan.version_code || 1,
        fileSize: scan.file_size,
        sha256: scan.sha256,
      },
      audit: {
        scanId: scan.id,
        status: scan.status,
        securityScore: scan.security_score,
        riskLevel: scan.risk_level,
        startedAt: scan.started_at,
        completedAt: scan.completed_at,
      },
      metrics: {
        totalVulnerabilities: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: vulnerabilities.filter(v => v.severity === 'LOW').length,
        totalPermissions: permissions.length,
        totalComponents: components.length,
        totalSecretsDetected: secrets.length,
        totalNetworkFindings: networkFindings.length,
      },
      vulnerabilities: vulnerabilities.map(v => ({
        id: v.id,
        title: v.title,
        severity: v.severity,
        confidence: v.confidence,
        category: v.category,
        analyzer: v.analyzer,
        source: v.source,
        status: v.status,
        analystNote: v.analyst_note,
        description: v.description,
        evidence: v.evidence,
        location: v.location,
        impact: v.impact,
        recommendation: v.recommendation,
        cwe: v.cwe,
        owaspCategory: v.owasp_category,
      })),
      secrets: secrets.map(s => ({
        id: s.id,
        secretType: s.secret_type,
        severity: s.severity,
        location: s.location,
        maskedValue: s.masked_value,
      })),
      networkFindings: networkFindings.map(n => ({
        id: n.id,
        type: n.type,
        severity: n.severity,
        description: n.description,
        evidence: n.evidence,
      })),
      permissions: permissions.map(p => ({
        id: p.id,
        permissionName: p.permission_name,
        dangerLevel: p.danger_level,
        description: p.description,
      })),
      components: components.map(c => ({
        id: c.id,
        componentType: c.component_type,
        componentName: c.component_name,
        exported: Boolean(c.exported),
        permission: c.permission,
      })),
    };
  }

  /**
   * Generates RFC 4180 compliant CSV export for findings
   */
  static generateCsvReport(vulnerabilities) {
    const headers = [
      'Finding ID',
      'Title',
      'Severity',
      'Confidence',
      'Category',
      'Analyzer',
      'Source Location',
      'Status',
      'CWE',
      'OWASP Mobile Category',
      'Description',
      'Observed Evidence',
      'Security Impact',
      'Remediation Guidance',
      'Analyst Note',
    ];

    const escapeCsv = (val) => {
      if (val === null || val === undefined) return '""';
      let str = String(val);
      // Mitigate CSV Formula Injection (DDE) by prefixing dangerous formula triggers
      if (/^[=\+\-@\t\r%]/.test(str)) {
        str = "'" + str;
      }
      str = str.replace(/"/g, '""');
      return `"${str}"`;
    };

    const rows = [headers.map(escapeCsv).join(',')];

    for (const v of vulnerabilities) {
      const row = [
        escapeCsv(v.id),
        escapeCsv(v.title),
        escapeCsv(v.severity),
        escapeCsv(v.confidence),
        escapeCsv(v.category),
        escapeCsv(v.analyzer),
        escapeCsv(v.location || v.source),
        escapeCsv(v.status),
        escapeCsv(v.cwe),
        escapeCsv(v.owasp_category),
        escapeCsv(v.description),
        escapeCsv(v.evidence),
        escapeCsv(v.impact),
        escapeCsv(v.recommendation),
        escapeCsv(v.analyst_note),
      ];
      rows.push(row.join(','));
    }

    return rows.join('\r\n');
  }
}

module.exports = ReportService;
