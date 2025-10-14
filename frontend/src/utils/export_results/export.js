const downloadFile = (content, fileName, contentType) => {
    const encodedUri = encodeURI(contentType + content);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", fileName);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
};

export const exportToCSV = (results, targetIp) => {
    const headers = 'Port,Status,Latency (ms)\n';
    const rows = results.map(r => `${r.port},${r.status},${r.latency_ms || 'N/A'}`).join('\n');
    downloadFile(headers + rows, `scan_results_${targetIp}.csv`, "data:text/csv;charset=utf-8,");
};

export const exportToJSON = (results, targetIp) => {
    const jsonContent = JSON.stringify(results, null, 2);
    downloadFile(jsonContent, `scan_results_${targetIp}.json`, "data:text/json;charset=utf-8,");
};