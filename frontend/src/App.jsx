/**
 * App Component
 * Root component that handles application routing and layout
 */
import React from 'react';
import { Routes, Route } from 'react-router-dom';
import HomePage from './components/HomePage';
import ScanPage from './components/ScanPage';
import LoginPage from './components/LoginPage';
import RegisterPage from './components/RegisterPage';
import VerifyOTPPage from './components/VerifyOTPPage';
import ProtectedRoute from './components/ProtectedRoute';
import Navbar from './components/Navbar';
import './App.css';
import './components/Navbar.css';

function App() {
  return (
    <div className="App">
      <Navbar />
      <Routes>
        {/* Public routes - accessible without authentication */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/verify-otp" element={<VerifyOTPPage />} />

        {/* Protected routes - require authentication */}
        <Route
          path="/"
          element={(
            <ProtectedRoute>
              <HomePage />
            </ProtectedRoute>
          )}
        />
        <Route
          path="/scan/:scanType"
          element={(
            <ProtectedRoute>
              <ScanPage />
            </ProtectedRoute>
          )}
        />
      </Routes>
    </div>
  );
}

export default App;
