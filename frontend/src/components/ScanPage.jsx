/**
 * ScanPage Component
 *
 * Provides a dynamic interface for configuring and executing different types of port scans.
 * Supports 12 scan types including TCP Connect, SYN, FIN, XMAS, NULL, ACK, Window,
 * Idle, UDP, IP Protocol Scan, and OS Detection.
 *
 * Features:
 * - Dynamic form fields based on scan type
 * - Real-time scan execution with loading states
 * - Multiple result display formats (port scans, protocol scans, OS detection)
 * - CSV and JSON export functionality
 * - JWT authentication for API requests
 *
 * @component
 */
import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import { exportToCSV, exportToJSON } from '../utils/export_results/export';
import { getToken } from '../services/authService';
import IPProtocolResult from './IPProtocolResult';
import OSResult from './OSResult';

function ScanPage() {
  // Extract scan type from URL parameters
  const { scanType } = useParams();
  const navigate = useNavigate();

  // Form input states
  const [targetIp, setTargetIp] = useState(''); // Target IP address or hostname
  const [ports, setPorts] = useState('1-100'); // Port specification (single, comma-separated, or range)
  const [zombieIp, setZombieIp] = useState(''); // Zombie host IP for Idle scan

  // Result states for different scan types
  const [portResults, setPortResults] = useState([]); // Array of port scan results
  const [ipProtocolResult, setIpProtocolResult] = useState(null); // IP Protocol scan result object
  const [osResult, setOsResult] = useState(null); // OS Detection result object

  // UI states
  const [isLoading, setIsLoading] = useState(false); // Loading state during scan execution
  const [error, setError] = useState(''); // Error message display

  // Scan type detection flags
  const isIdleScan = scanType === 'Idle';
  const isIpProtocolScan = scanType === 'IP Protocol Scan';
  const isOsDetection = scanType === 'OS-Detection';
  const requiresPorts = !isIpProtocolScan && !isOsDetection; // Determine if ports field is needed

  /**
   * Handles scan form submission
   * Validates authentication, prepares payload based on scan type,
   * executes scan via API, and processes results
   *
   * @param {Event} e - Form submit event
   */
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    // Clear previous results and errors
    setPortResults([]);
    setIpProtocolResult(null);
    setOsResult(null);
    setError('');

    // Verify authentication token
    const token = getToken();
    if (!token) {
      setError('Authentication required. Please log in.');
      setIsLoading(false);
      return;
    }

    // Prepare request payload based on scan type
    const payload = {
      target_ip: targetIp,
      scan_type: scanType,
    };

    // Add ports field only for port-based scans
    if (requiresPorts) {
      payload.ports = ports;
    }

    // Add zombie_ip field only for Idle scan
    if (isIdleScan) {
      payload.zombie_ip = zombieIp;
    }

    try {
      // Execute scan request with authentication header
      const response = await axios.post(
        'http://localhost:5000/api/scan',
        payload,
        { headers: { Authorization: `Bearer ${token}` } },
      );

      console.log('Backend Response:', response.data); // eslint-disable-line no-console

      // Process response based on data format
      if (response.data.error) {
        // Backend returned error in response
        setError(response.data.error);
      } else if (Array.isArray(response.data)) {
        // Port scan results - array of port objects
        setPortResults(response.data);
      } else if (response.data.protocols) {
        // IP Protocol Scan results - object with protocols array
        setIpProtocolResult(response.data);
      } else if (response.data.os_guess) {
        // OS Detection results - object with OS information
        setOsResult(response.data);
      } else {
        // Unexpected response format
        setError('Received unexpected data format from backend.');
      }
    } catch (err) {
      // Handle API errors
      const errorMsg = err.response?.data?.error || err.message || 'An unexpected error occurred.';

      if (err.response?.status === 401) {
        // Authentication failed - token expired or invalid
        setError('Authentication failed. Please log in again.');
      } else {
        // Other errors (network, server, validation)
        setError(errorMsg);
      }

      console.error('Scan Error:', err); // eslint-disable-line no-console
    } finally {
      // Always clear loading state
      setIsLoading(false);
    }
  };

  return (
    <div className="scan-page">
      {/* Page header with back button and scan type title */}
      <div className="scan-header">
        <button type="button" onClick={() => navigate('/')} className="back-button">
          ← Back
        </button>
        {/* Conditional title rendering for different scan types */}
        {scanType === 'IP Protocol Scan' || scanType === 'OS-Detection' ? (<h1>{scanType}</h1>) : (
          <h1>
            {scanType}
            {' '}
            Scan
          </h1>
        )}
        <p>Configure and execute scan</p>
      </div>

      {/* Scan configuration form */}
      <form onSubmit={handleSubmit} className="scan-form">
        {/* Target IP input - required for all scan types */}
        <div className="form-group">
          <label htmlFor="targetIp">Target IP Address</label>
          <input
            id="targetIp"
            type="text"
            value={targetIp}
            onChange={(e) => setTargetIp(e.target.value)}
            placeholder="e.g., 192.168.1.1 or example.com"
            required
          />
        </div>

        {/* Port input - only shown for port-based scans */}
        { requiresPorts && (
          <div className="form-group">
            <label htmlFor="ports">{isIdleScan ? 'Target Port' : 'Port Range'}</label>
            <input
              id="ports"
              type="text"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder={isIdleScan ? 'e.g., 80' : 'e.g., 80, 443 or 1-1024'}
              required={requiresPorts}
            />
          </div>
        )}

        {/* Zombie IP input - only shown for Idle scan */}
        { isIdleScan && (
          <div className="form-group">
            <label htmlFor="zombieIp">Zombie IP Address</label>
            <input
              id="zombieIp"
              type="text"
              value={zombieIp}
              onChange={(e) => setZombieIp(e.target.value)}
              placeholder="e.g., 192.168.1.5"
              required={isIdleScan}
            />
          </div>
        )}

        {/* Submit button with loading state */}
        <div className="form-group full-width">
          <button type="submit" className="submit-btn" disabled={isLoading}>
            {isLoading ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>
      </form>

      {/* Error message display */}
      {/* Error message display */}
      {error && <div className="error">{error}</div>}

      {/* Port scan results table */}
      {portResults.length > 0 && (
        <div className="results-container">
          <div className="results-header">
            <h2>
              Scan Results for
              {targetIp}
            </h2>
            {/* Export buttons for CSV and JSON formats */}
            <div className="export-buttons">
              <button type="button" onClick={() => exportToCSV(portResults, targetIp)}>Export CSV</button>
              <button type="button" onClick={() => exportToJSON(portResults, targetIp)}>Export JSON</button>
            </div>
          </div>

          {/* Results table with port, status, and latency columns */}
          <table className="results-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Status</th>
                <th>Latency (ms)</th>
              </tr>
            </thead>
            <tbody>
              {portResults.map((result) => (
                <tr key={result.port}>
                  <td>{result.port}</td>
                  <td className={`status-${result.status ? String(result.status).replace(/[^a-zA-Z0-9]/g, '') : 'Error'}`}>
                    {result.status || `Error: ${result.detail || 'Unknown'}`}
                  </td>
                  <td>{result.latency_ms || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* IP Protocol Scan results component */}
      {ipProtocolResult && (
        <IPProtocolResult data={ipProtocolResult} targetIp={targetIp} />
      )}

      {/* OS Detection results component */}
      {osResult && (
        <OSResult data={osResult} targetIp={targetIp} />
      )}
    </div>
  );
}

export default ScanPage;
