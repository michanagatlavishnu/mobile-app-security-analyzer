import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import authService from '../services/authService';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => {
    try {
      return localStorage.getItem('auth_token');
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState(true);

  // Load current user profile from token
  const loadCurrentUser = useCallback(async () => {
    const storedToken = localStorage.getItem('auth_token');
    if (!storedToken) {
      setUser(null);
      setLoading(false);
      return;
    }

    try {
      const data = await authService.getCurrentUser();
      if (data && data.user) {
        setUser(data.user);
      } else {
        setUser(null);
      }
    } catch {
      // Token expired or invalid
      try {
        localStorage.removeItem('auth_token');
      } catch {
        // Ignore
      }
      setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCurrentUser();
  }, [loadCurrentUser]);

  // Login handler
  const login = async (email, password) => {
    const data = await authService.login({ email, password });
    if (data.token) {
      try {
        localStorage.setItem('auth_token', data.token);
      } catch {
        // Ignore
      }
      setToken(data.token);
      setUser(data.user);
    }
    return data;
  };

  // Register handler
  const register = async (name, email, password) => {
    const data = await authService.register({ name, email, password });
    if (data.token) {
      try {
        localStorage.setItem('auth_token', data.token);
      } catch {
        // Ignore
      }
      setToken(data.token);
      setUser(data.user);
    }
    return data;
  };

  // Logout handler
  const logout = () => {
    try {
      localStorage.removeItem('auth_token');
    } catch {
      // Ignore
    }
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token,
        isAdmin: user?.role === 'admin',
        loading,
        login,
        logout,
        register,
        loadCurrentUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

/**
 * Route Guard Component for Protected Pages
 */
export function ProtectedRoute({ children, requireAdmin = false }) {
  const { isAuthenticated, isAdmin, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-cyan-400">
        <div className="flex flex-col items-center">
          <div className="w-8 h-8 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin mb-3"></div>
          <p className="text-xs font-mono text-slate-400">Authenticating session...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requireAdmin && !isAdmin) {
    return (
      <Navigate
        to="/dashboard"
        state={{ accessDenied: 'Access denied: Administrator privileges required to access the Admin Portal.' }}
        replace
      />
    );
  }

  return children;
}
