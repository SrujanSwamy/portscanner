import React from 'react';
import PropTypes from 'prop-types';

function OSResult({ data, targetIp }) {
  // Checking if data exists before trying to access its properties
  if (!data) {
    return (
      <div className="results-container">
        <div className="results-header">
          <h2>
            OS Detection Results for
            {targetIp}
          </h2>
        </div>
        <p>No OS detection data available.</p>
      </div>
    );
  }

  return (
    <div className="results-container">
      <div className="results-header">
        <h2>
          OS Detection Results for
          {targetIp}
        </h2>
        {/* Export buttons are typically not needed for single OS result */}
      </div>
      <table className="results-table">
        <thead>
          <tr>
            <th>Property</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>OS Guess</td>
            <td>
              {/* Displaying the OS guess, handle potential undefined */}
              <strong>{data.os_guess || 'N/A'}</strong>
            </td>
          </tr>
          <tr>
            <td>Detail</td>
            <td>
              {/* Displaying the detail, handle potential undefined */}
              {data.detail || 'N/A'}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

OSResult.propTypes = {
  data: PropTypes.shape({
    os_guess: PropTypes.string,
    detail: PropTypes.string,
  }).isRequired,
  targetIp: PropTypes.string.isRequired,
};

export default OSResult;
