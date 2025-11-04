/**
 * AuthContext - Authentication Context Provider
 *
 * Manages global authentication state for the application including:
 * - User authentication status
 * - JWT token management
 * - Login, registration, and OTP verification
 * - Last login timestamp tracking
 * - Token persistence across browser sessions
 *
 * This context provides authentication functionality to all child components
 * and handles token storage/retrieval via localStorage.
 *
 * @module AuthContext
 */
import React, {
  createContext, useContext, useState, useEffect, useMemo,
} from 'react';
import PropTypes from 'prop-types';
import * as authService from '../services/authService';

// Create authentication context
const AuthContext = createContext(null);

/**
 * AuthProvider Component
 *
 * Wraps the application to provide authentication state and methods
 * to all child components via React Context API.
 *
 * @component
 * @param {Object} props - Component props
 * @param {React.ReactNode} props.children - Child components to wrap
 */
export function AuthProvider({ children }) {
  // Authentication state management
  const [token, setToken] = useState(authService.getToken()); // JWT token from localStorage
  const [isAuthenticated, setIsAuthenticated] = useState(!!token); // Authentication status
  const [isLoading, setIsLoading] = useState(false); // Loading state for async operations
  const [lastLogin, setLastLogin] = useState(authService.getLastLogin()); // Last login timestamp

  /**
   * Effect: Initialize authentication state on app load
   * Validates any existing token from localStorage and restores session
   * For enhanced security, consider adding token validation with backend
   */
  useEffect(() => {
    const storedToken = authService.getToken();
    if (storedToken) {
      setToken(storedToken);
      setIsAuthenticated(true);
      setLastLogin(authService.getLastLogin());
    }
  }, []);

  /**
   * Authenticates user with email and password
   * Stores token and updates authentication state on success
   *
   * @param {string} email - User's email address
   * @param {string} password - User's password
   * @returns {Promise<Object>} Response data containing token and lastLogin
   * @throws {Error} Authentication error from API
   */
  const login = async (email, password) => {
    setIsLoading(true);
    try {
      const data = await authService.login(email, password);
      setToken(data.token);
      setLastLogin(data.lastLogin);
      setIsAuthenticated(true);
      setIsLoading(false);
      return data;
    } catch (error) {
      setIsLoading(false);
      throw error;
    }
  };

  /**
   * Registers a new user account
   * Sends OTP to user's email for verification
   *
   * @param {string} email - User's email address
   * @param {string} password - User's chosen password
   * @returns {Promise<Object>} Response data with success status and message
   * @throws {Error} Registration error from API
   */
  const register = async (email, password) => {
    setIsLoading(true);
    try {
      const data = await authService.register(email, password);
      setIsLoading(false);
      return data;
    } catch (error) {
      setIsLoading(false);
      throw error;
    }
  };

  /**
   * Verifies user's email with OTP code
   * Completes the registration process by validating the OTP
   *
   * @param {string} email - User's email address
   * @param {string} otp - 6-digit OTP code from email
   * @returns {Promise<Object>} Response data with verification status
   * @throws {Error} Verification error from API (invalid/expired OTP)
   */
  const verifyOtp = async (email, otp) => {
    setIsLoading(true);
    try {
      const data = await authService.verifyOtp(email, otp);
      setIsLoading(false);
      return data;
    } catch (error) {
      setIsLoading(false);
      throw error;
    }
  };

  /**
   * Logs out the current user
   * Clears token from localStorage and resets authentication state
   */
  const logout = () => {
    authService.logout();
    setToken(null);
    setLastLogin(null);
    setIsAuthenticated(false);
  };

  /**
   * Memoized context value to prevent unnecessary re-renders
   * Only recomputes when dependencies change
   */
  const value = useMemo(() => ({
    token,
    isAuthenticated,
    isLoading,
    lastLogin,
    login,
    register,
    verifyOtp,
    logout,
  }), [token, isAuthenticated, isLoading, lastLogin]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// PropTypes validation for AuthProvider
AuthProvider.propTypes = {
  children: PropTypes.node.isRequired,
};

/**
 * Custom hook to access authentication context
 * Must be used within AuthProvider component tree
 *
 * @returns {Object} Authentication context value with state and methods
 * @example
 * const { isAuthenticated, login, logout } = useAuth();
 */
export const useAuth = () => useContext(AuthContext);
