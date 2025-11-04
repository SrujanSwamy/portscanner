/**
 * Authentication Service
 * Handles API calls for user authentication and token management
 */

// Backend API base URL
const API_URL = 'http://[::1]:5000/api';

/**
 * Registers a new user and sends OTP via email
 * @param {string} email - User's email address
 * @param {string} password - User's password
 * @returns {Promise<Object>} Registration response
 */
export const register = async (email, password) => {
  const response = await fetch(`${API_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return response.json();
};

/**
 * Verifies user email with 6-digit OTP (expires in 10 minutes)
 * @param {string} email - User's email address
 * @param {string} otp - 6-digit OTP code
 * @returns {Promise<Object>} Verification response
 */
export const verifyOtp = async (email, otp) => {
  const response = await fetch(`${API_URL}/verify-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, otp }),
  });
  return response.json();
};

/**
 * Authenticates user and stores JWT token in localStorage
 * @param {string} email - User's email address
 * @param {string} password - User's password
 * @returns {Promise<Object>} Login response with token
 * @throws {Error} Login failure error
 */
export const login = async (email, password) => {
  const response = await fetch(`${API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.message || 'Login failed');
  }

  const data = await response.json();

  // Store authentication data
  if (data.token) {
    localStorage.setItem('authToken', data.token);
  }
  if (data.lastLogin) {
    localStorage.setItem('lastLogin', data.lastLogin);
  } else {
    localStorage.removeItem('lastLogin');
  }

  return data;
};

/**
 * Logs out user by removing token from localStorage
 */
export const logout = () => {
  localStorage.removeItem('authToken');
};

/**
 * Gets stored JWT token
 * @returns {string|null} JWT token or null
 */
export const getToken = () => localStorage.getItem('authToken');

/**
 * Gets last login timestamp
 * @returns {string|null} ISO timestamp or null
 */
export const getLastLogin = () => localStorage.getItem('lastLogin');
