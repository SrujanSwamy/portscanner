/**
 * Export Utilities
 * Handles exporting scan results to CSV and JSON formats
 */

/**
 * Exports scan results to CSV format
 * @param {Array} results - Array of scan result objects
 * @param {string} targetIp - Target IP address for filename
 */
export const exportToCSV = (results, targetIp) => {
  if (!results || results.length === 0) {
    alert('No results to export');
    return;
  }

  // Create CSV content
  const headers = ['Port', 'Status', 'Latency (ms)'];
  const csvRows = results.map((result) => [
    result.port,
    result.status,
    result.latency_ms || 'N/A',
  ].join(','));

  const csvContent = [headers.join(','), ...csvRows].join('\n');

  // Trigger download
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);

  link.setAttribute('href', url);
  link.setAttribute('download', `scan_results_${targetIp}_${Date.now()}.csv`);
  link.style.visibility = 'hidden';

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

/**
 * Exports scan results to JSON format with metadata
 * @param {Array} results - Array of scan result objects
 * @param {string} targetIp - Target IP address for filename
 */
export const exportToJSON = (results, targetIp) => {
  if (!results || results.length === 0) {
    alert('No results to export');
    return;
  }

  // Build export data with metadata
  const exportData = {
    metadata: {
      target_ip: targetIp,
      scan_date: new Date().toISOString(),
      total_ports_scanned: results.length,
      open_ports: results.filter((r) => r.status === 'Open').length,
      closed_ports: results.filter((r) => r.status === 'Closed').length,
      filtered_ports: results.filter((r) => r.status.includes('Filtered')).length,
    },
    results,
  };

  const jsonContent = JSON.stringify(exportData, null, 2);

  // Trigger download
  const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);

  link.setAttribute('href', url);
  link.setAttribute('download', `scan_results_${targetIp}_${Date.now()}.json`);
  link.style.visibility = 'hidden';

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};
