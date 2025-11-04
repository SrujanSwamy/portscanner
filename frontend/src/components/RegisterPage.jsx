import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
/**
 * RegisterPage Component
 * Handles user registration with email and password
 * Validates password confirmation and navigates to OTP verification on success
 */
function RegisterPage() {
  // Form state management
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');

  // Authentication context and navigation hooks
  const { register, isLoading } = useAuth();
  const navigate = useNavigate();

  /**
   * Handles form submission for user registration
   * @param {Event} e - Form submit event
   */
  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validate password confirmation
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Clear previous errors
    setError('');

    try {
      // Call registration API via auth context
      const data = await register(email, password);

      if (data.success) {
        // Navigate to OTP verification page with email in state
        navigate('/verify-otp', { state: { email } });
      } else {
        // Display error message from API
        setError(data.message || 'Registration failed');
      }
    } catch (err) {
      // Handle network or unexpected errors
      setError(err.message || 'Failed to register.');
    }
  };

  return (
    <div className="auth-container">
      <form className="scan-form auth-form" onSubmit={handleSubmit}>
        <h1 className="auth-title">Create Account</h1>

        {/* Display error message if exists */}
        {error && <div className="error full-width">{error}</div>}

        {/* Email input field */}
        <div className="form-group full-width">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
          />
        </div>

        {/* Password input field */}
        <div className="form-group full-width">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Min. 8 characters"
            required
          />
        </div>

        {/* Confirm password input field */}
        <div className="form-group full-width">
          <label htmlFor="confirmPassword">Confirm Password</label>
          <input
            type="password"
            id="confirmPassword"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="••••••••"
            required
          />
        </div>

        {/* Submit button with loading state */}
        <div className="form-group full-width">
          <button type="submit" className="submit-btn" disabled={isLoading}>
            {isLoading ? 'Registering...' : 'Register'}
          </button>
        </div>

        {/* Link to login page for existing users */}
        <p className="auth-switch-link">
          Already have an account?
          {' '}
          <Link to="/login">Login</Link>
        </p>
      </form>
    </div>
  );
}

export default RegisterPage;
