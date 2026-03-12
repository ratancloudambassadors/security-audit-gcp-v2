const ExcelJS = require('exceljs');
const PDFDocument = require('pdfkit');

/**
 * Generates an Excel report as a Buffer
 * @param {Object} results - Audit results object
 * @returns {Promise<Buffer>}
 */
async function generateExcelReport(results) {
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'AuditScope';
    workbook.created = new Date();

    // Summary Sheet
    const summarySheet = workbook.addWorksheet('Summary');
    summarySheet.columns = [
        { header: 'Metric', key: 'metric', width: 30 },
        { header: 'Value', key: 'value', width: 40 }
    ];

    summarySheet.addRow({ metric: 'Platform', value: results.platform });
    summarySheet.addRow({ metric: 'Project ID', value: results.projectId });
    summarySheet.addRow({ metric: 'Timestamp', value: results.timestamp });

    // Calculate overall summary
    let totalHigh = 0, totalMedium = 0, totalLow = 0, totalSecure = 0;
    if (results.services) {
        Object.values(results.services).forEach(service => {
            if (service.summary) {
                totalHigh += (service.summary.high || service.summary.critical || 0);
                totalMedium += (service.summary.medium || 0);
                totalLow += (service.summary.low || 0);
                totalSecure += (service.summary.secure || 0);
            }
        });
    }

    summarySheet.addRow({ metric: 'Critical/High Issues', value: totalHigh });
    summarySheet.addRow({ metric: 'Medium Issues', value: totalMedium });
    summarySheet.addRow({ metric: 'Low Issues', value: totalLow });
    summarySheet.addRow({ metric: 'Secure Assets', value: totalSecure });

    // Vulnerabilities Sheet
    const vulnSheet = workbook.addWorksheet('Vulnerabilities');
    vulnSheet.columns = [
        { header: 'Service', key: 'service', width: 20 },
        { header: 'Asset', key: 'asset', width: 30 },
        { header: 'Severity', key: 'severity', width: 15 },
        { header: 'Description', key: 'description', width: 60 },
        { header: 'Remediation', key: 'remediation', width: 60 }
    ];

    // Inventory Sheet
    const invSheet = workbook.addWorksheet('Inventory');
    invSheet.columns = [
        { header: 'Service', key: 'service', width: 20 },
        { header: 'Category', key: 'category', width: 20 },
        { header: 'Resource ID', key: 'id', width: 30 },
        { header: 'Type', key: 'type', width: 20 },
        { header: 'Details', key: 'details', width: 40 },
        { header: 'Remarks', key: 'remarks', width: 20 }
    ];

    // Populate sheets
    if (results.services) {
        Object.entries(results.services).forEach(([serviceName, data]) => {
            if (data.vulnerabilities) {
                data.vulnerabilities.forEach(v => {
                    vulnSheet.addRow({
                        service: serviceName,
                        asset: v.asset,
                        severity: v.severity,
                        description: v.description,
                        remediation: v.remediation
                    });
                });
            }
            if (data.inventory) {
                data.inventory.forEach(i => {
                    invSheet.addRow({
                        service: serviceName,
                        category: i.category,
                        id: i.id,
                        type: i.type,
                        details: i.details,
                        remarks: i.remarks
                    });
                });
            }
        });
    }

    // Styling
    [summarySheet, vulnSheet, invSheet].forEach(sheet => {
        sheet.getRow(1).font = { bold: true };
        sheet.getRow(1).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE0E0E0' }
        };
    });

    return await workbook.xlsx.writeBuffer();
}

/**
 * Generates a PDF report as a Buffer
 * @param {Object} results - Audit results object
 * @returns {Promise<Buffer>}
 */
async function generatePDFReport(results) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 50 });
        let buffers = [];
        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => {
            const pdfData = Buffer.concat(buffers);
            resolve(pdfData);
        });

        // Header
        doc.fillColor('#1a73e8').fontSize(24).text('Cloud Security Audit Report', { align: 'center' });
        doc.moveDown();
        doc.fillColor('#444444').fontSize(14).text(`Platform: ${results.platform}`, { align: 'left' });
        doc.text(`Project ID: ${results.projectId}`);
        doc.text(`Generated on: ${new Date().toLocaleString()}`);
        doc.moveDown();

        doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke('#dddddd');
        doc.moveDown();

        // Summary Section
        doc.fillColor('#1a73e8').fontSize(18).text('Executive Summary');
        doc.moveDown(0.5);

        let totalHigh = 0, totalMedium = 0, totalLow = 0;
        if (results.services) {
            Object.values(results.services).forEach(service => {
                if (service.summary) {
                    totalHigh += (service.summary.high || service.summary.critical || 0);
                    totalMedium += (service.summary.medium || 0);
                    totalLow += (service.summary.low || 0);
                }
            });
        }

        doc.fillColor('#333333').fontSize(12);
        doc.text(`Critical Issues: ${totalHigh}`, { continued: true }).fillColor(totalHigh > 0 ? '#d93025' : '#1e8e3e').text(`  ${totalHigh > 0 ? '(Action Required)' : '(Clean)'}`);
        doc.fillColor('#333333').text(`Medium Risks: ${totalMedium}`);
        doc.text(`Low Risks: ${totalLow}`);
        doc.moveDown();

        // Detailed Findings
        doc.fillColor('#1a73e8').fontSize(18).text('Top Vulnerabilities');
        doc.moveDown(0.5);

        let count = 0;
        if (results.services) {
            Object.entries(results.services).forEach(([serviceName, data]) => {
                if (data.vulnerabilities && count < 15) { // Limit to top 15 for PDF brevity
                    data.vulnerabilities.forEach(v => {
                        if (count >= 15) return;
                        doc.fillColor('#333333').fontSize(12).font('Helvetica-Bold').text(`${v.severity}: ${v.asset}`);
                        doc.font('Helvetica').fontSize(10).text(v.description);
                        doc.fillColor('#1e8e3e').text(`Remediation: ${v.remediation}`);
                        doc.moveDown(0.5);
                        count++;
                    });
                }
            });
        }

        if (count === 0) {
            doc.fillColor('#1e8e3e').text('No significant vulnerabilities found.');
        }

        doc.moveDown();
        doc.fontSize(10).fillColor('#999999').text('This report was automatically generated. Detailed inventory and findings are available in the attached Excel sheet.', { align: 'center' });

        doc.end();
    });
}

module.exports = {
    generateExcelReport,
    generatePDFReport
};
