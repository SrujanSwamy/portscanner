/**
 * VerifyOTPPage Component
 *
 * Handles email verification through One-Time Password (OTP) validation.
 * Users receive a 6-digit OTP via email after registration that must be
 * verified within 10 minutes to activate their account.
 *
 * Flow:
 * 1. User registers and receives OTP via email
 * 2. User enters OTP on this page
 * 3. Upon successful verification, redirects to login page
 *
 * @component
 */
import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function VerifyOTPPage() {
  // Form state management
  const [otp, setOtp] = useState(''); // 6-digit OTP input
  const [error, setError] = useState(''); // Error message display
  const [message, setMessage] = useState(''); // Success message display

  // Authentication context and navigation hooks
  const { verifyOtp, isLoading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Extract email from location state (passed from registration page)
  const email = location.state?.email;

  /**
   * Handles OTP verification form submission
   * Validates the OTP with backend and redirects to login on success
   *
   * @param {Event} e - Form submit event
   */
  const handleSubmit = async (e) => {
    e.preventDefault();

    // Clear previous messages
    setError('');
    setMessage('');

    try {
      // Call verification API via auth context
      const data = await verifyOtp(email, otp);

      if (data.success) {
        // Show success message and redirect after 2 seconds
        setMessage('Verification successful! Redirecting to login...');
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        // Display error message from API
        setError(data.message || 'Invalid or expired OTP.');
      }
    } catch (err) {
      // Handle network or unexpected errors
      setError(err.message || 'Failed to verify OTP.');
    }
  };

  return (
    <div className="auth-container">
      <form className="scan-form auth-form" onSubmit={handleSubmit}>
        <h1 className="auth-title">Verify Your Email</h1>

        {/* Display email where OTP was sent */}
        <p className="auth-subtitle">
          An OTP has been sent to
          {' '}
          <strong>{email}</strong>
          .
        </p>

        {/* Display error message if exists */}
        {error && <div className="error full-width">{error}</div>}

        {/* Display success message if exists */}
        {message && <div className="success-msg full-width">{message}</div>}

        {/* OTP input field - 6 digits only */}
        <div className="form-group full-width">
          <label htmlFor="otp">Enter 6-Digit OTP</label>
          <input
            type="text"
            id="otp"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            placeholder="123456"
            maxLength="6"
            required
          />
        </div>

        {/* Submit button with loading state */}
        <div className="form-group full-width">
          <button type="submit" className="submit-btn" disabled={isLoading}>
            {isLoading ? 'Verifying...' : 'Verify Account'}
          </button>
        </div>
      </form>
    </div>
  );
}

export default VerifyOTPPage;
