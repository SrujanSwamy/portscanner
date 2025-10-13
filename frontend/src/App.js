import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
    const [targetIp, setTargetIp] = useState('');
    const [ports, setPorts] = useState('1-100');
    const [scanType, setScanType] = useState('TCP Connect');
    const [zombieIp, setZombieIp] = useState('');

    const [results, setResults] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const scanTypes = [
        "TCP Connect", "TCP SYN", "TCP FIN", "TCP Xmas", "TCP Null",
        "TCP ACK", "TCP Window", "UDP", "Idle"
    ];

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setResults([]);
        setError('');

        try {
            const response = await axios.post('http://localhost:5000/scan', {
                target_ip: targetIp,
                ports,
                scan_type: scanType,
                zombie_ip: scanType === 'Idle' ? zombieIp : undefined,
            });
            setResults(response.data);
        } catch (err) {
            setError(err.response?.data?.error || 'An unexpected error occurred.');
        } finally {
            setIsLoading(false);
        }
    };

    const exportToCSV = () => {
        const headers = 'Port,Status,Latency (ms)\n';
        const rows = results.map(r => `${r.port},${r.status},${r.latency_ms || 'N/A'}`).join('\n');
        const csvContent = "data:text/csv;charset=utf-8," + headers + rows;
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `scan_results_${targetIp}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const exportToJSON = () => {
        const jsonContent = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(results, null, 2));
        const link = document.createElement("a");
        link.setAttribute("href", jsonContent);
        link.setAttribute("download", `scan_results_${targetIp}.json`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className="App">
            <header className="App-header">
                <h1>Network Port Scanner</h1>
                <p>A tool for educational purposes, implemented from scratch.</p>
            </header>

            <form onSubmit={handleSubmit} className="scan-form">
                <div className="form-group">
                    <label htmlFor="targetIp">Target IP Address</label>
                    <input
                        id="targetIp"
                        type="text"
                        value={targetIp}
                        onChange={(e) => setTargetIp(e.target.value)}
                        placeholder="e.g., 127.0.0.1"
                        required
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="ports">Port Range</label>
                    <input
                        id="ports"
                        type="text"
                        value={ports}
                        onChange={(e) => setPorts(e.target.value)}
                        placeholder="e.g., 80, 443 or 1-1024"
                        required
                    />
                </div>
                <div className={`form-group ${scanType === 'Idle' ? '' : 'full-width'}`}>
                    <label htmlFor="scanType">Scan Technique</label>
                    <select id="scanType" value={scanType} onChange={(e) => setScanType(e.target.value)}>
                        {scanTypes.map(type => <option key={type} value={type}>{type}</option>)}
                    </select>
                </div>
                {scanType === 'Idle' && (
                    <div className="form-group">
                        <label htmlFor="zombieIp">Zombie IP Address</label>
                        <input
                            id="zombieIp"
                            type="text"
                            value={zombieIp}
                            onChange={(e) => setZombieIp(e.target.value)}
                            placeholder="e.g., 192.168.1.5"
                            required
                        />
                    </div>
                )}
                <div className="form-group full-width">
                    <button type="submit" className="submit-btn" disabled={isLoading}>
                        {isLoading ? 'Scanning...' : 'Start Scan'}
                    </button>
                </div>
            </form>

            {error && <div className="error">{error}</div>}

            {results.length > 0 && (
                <div className="results-container">
                    <div className="results-header">
                        <h2>Scan Results for {targetIp}</h2>
                        <div className="export-buttons">
                            <button onClick={exportToCSV}>Export CSV</button>
                            <button onClick={exportToJSON}>Export JSON</button>
                        </div>
                    </div>
                    <table className="results-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Status</th>
                                <th>Latency (ms)</th>
                            </tr>
                        </thead>
                        <tbody>
                            {results.map((result, index) => (
                                <tr key={index}>
                                    <td>{result.port}</td>
                                    <td className={`status-${result.status.replace('|', '')}`}>{result.status}</td>
                                    <td>{result.latency_ms || 'N/A'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

export default App;