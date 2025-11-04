import React from 'react';
import PropTypes from 'prop-types';

function IPProtocolResult({ data, targetIp }) {
  // data should be the object { protocols: [...] } or { error: '...' }
  const protocolResults = data?.protocols;

  // Handle case where the scan itself returned an error object
  if (data?.error) {
    return (
      <div className="results-container">
        <div className="results-header">
          <h2>
            IP Protocol Scan Results for
            {targetIp}
          </h2>
        </div>
        <div className="error">
          <strong>Scan Error:</strong>
          {' '}
          {data.error}
        </div>
      </div>
    );
  }

  // Handle case where protocols array is missing or empty
  if (!protocolResults || protocolResults.length === 0) {
    return (
      <div className="results-container">
        <div className="results-header">
          <h2>
            IP Protocol Scan Results for
            {targetIp}
          </h2>
        </div>
        <p>No protocol scan data available or scan failed.</p>
      </div>
    );
  }

  return (
    <div className="results-container">
      <div className="results-header">
        <h2>
          IP Protocol Scan Results for
          {targetIp}
        </h2>
      </div>
      <table className="results-table">
        <thead>
          <tr>
            <th>Protocol Number</th>
            <th>Protocol Name</th>
            <th>Status</th>
            
          </tr>
        </thead>
        <tbody>
          {protocolResults.map((result) => (
            <tr key={result.protocol_number}>
              <td>{result.protocol_number}</td>
              <td>{result.protocol_name}</td>
              <td className={`status-${result.status ? String(result.status).replace(/[^a-zA-Z0-9]/g, '') : 'unknown'}`}>
                {result.status || 'unknown'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

IPProtocolResult.propTypes = {
  data: PropTypes.shape({
    protocols: PropTypes.arrayOf(PropTypes.shape({
      protocol_number: PropTypes.number,
      protocol_name: PropTypes.string,
      status: PropTypes.string,
      latency_ms: PropTypes.number,
    })),
    error: PropTypes.string,
  }).isRequired,
  targetIp: PropTypes.string.isRequired,
};

export default IPProtocolResult;
