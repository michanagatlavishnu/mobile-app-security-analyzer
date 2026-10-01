const ReportService = require('../services/reportService');
const logger = require('../utils/logger');

/**
 * Streams generated PDF report for an authorized scan
 * GET /api/reports/:scanId/pdf
 */
async function downloadPdf(req, res, next) {
  try {
    const scanId = parseInt(req.params.scanId, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    if (isNaN(scanId)) {
      return res.status(400).json({ success: false, message: 'Invalid scan ID' });
    }

    const reportData = await ReportService.getFullScanReportData(scanId, userId, isAdmin);

    const filename = `security_report_scan_${scanId}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    ReportService.generatePdfReport(reportData, res);
  } catch (error) {
    if (error.message.includes('not found') || error.message.includes('denied')) {
      return res.status(404).json({ success: false, message: 'Scan record not found or access denied' });
    }
    logger.error(`Error generating PDF report for scan ${req.params.scanId}: ${error.message}`);
    next(error);
  }
}

/**
 * Returns structured sanitized JSON report export
 * GET /api/reports/:scanId/json
 */
async function exportJson(req, res, next) {
  try {
    const scanId = parseInt(req.params.scanId, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    if (isNaN(scanId)) {
      return res.status(400).json({ success: false, message: 'Invalid scan ID' });
    }

    const reportData = await ReportService.getFullScanReportData(scanId, userId, isAdmin);
    const jsonReport = ReportService.generateJsonReport(reportData);

    const filename = `security_report_scan_${scanId}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    return res.status(200).send(JSON.stringify(jsonReport, null, 2));
  } catch (error) {
    if (error.message.includes('not found') || error.message.includes('denied')) {
      return res.status(404).json({ success: false, message: 'Scan record not found or access denied' });
    }
    logger.error(`Error exporting JSON report for scan ${req.params.scanId}: ${error.message}`);
    next(error);
  }
}

/**
 * Returns RFC-4180 CSV export of findings
 * GET /api/reports/:scanId/csv
 */
async function exportCsv(req, res, next) {
  try {
    const scanId = parseInt(req.params.scanId, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    if (isNaN(scanId)) {
      return res.status(400).json({ success: false, message: 'Invalid scan ID' });
    }

    const reportData = await ReportService.getFullScanReportData(scanId, userId, isAdmin);
    const csvContent = ReportService.generateCsvReport(reportData.vulnerabilities);

    const filename = `vulnerabilities_scan_${scanId}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    return res.status(200).send(csvContent);
  } catch (error) {
    if (error.message.includes('not found') || error.message.includes('denied')) {
      return res.status(404).json({ success: false, message: 'Scan record not found or access denied' });
    }
    logger.error(`Error exporting CSV report for scan ${req.params.scanId}: ${error.message}`);
    next(error);
  }
}

module.exports = {
  downloadPdf,
  exportJson,
  exportCsv,
};
