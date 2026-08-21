import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { 
  getCurrentUserProfile, loginUser, registerUser,
  updateUserProfile, changeUserPassword, logoutUser 
} from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(
    localStorage.getItem('phishguard_token') || sessionStorage.getItem('phishguard_token') || null
  );
  const [loading, setLoading] = useState(true);

  const logout = useCallback(async () => {
    try {
      await logoutUser();
    } catch {
      // Ignore
    }
    localStorage.removeItem('phishguard_token');
    sessionStorage.removeItem('phishguard_token');
    setToken(null);
    setUser(null);
  }, []);

  const refreshUser = useCallback(async () => {
    const currentToken = localStorage.getItem('phishguard_token') || sessionStorage.getItem('phishguard_token');
    if (!currentToken) {
      setUser(null);
      setLoading(false);
      return null;
    }
    try {
      const profile = await getCurrentUserProfile();
      setUser(profile);
      return profile;
    } catch (err) {
      console.warn('Session expired or invalid:', err);
      logout();
      return null;
    } finally {
      setLoading(false);
    }
  }, [logout]);

  useEffect(() => {
    refreshUser();
  }, [token, refreshUser]);

  const saveToken = (accessToken, rememberMe = true) => {
    if (rememberMe) {
      localStorage.setItem('phishguard_token', accessToken);
      sessionStorage.removeItem('phishguard_token');
    } else {
      sessionStorage.setItem('phishguard_token', accessToken);
      localStorage.removeItem('phishguard_token');
    }
    setToken(accessToken);
  };

  const login = async (username_or_email, password, rememberMe = true) => {
    const data = await loginUser(username_or_email, password, rememberMe);
    saveToken(data.access_token, rememberMe);
    setUser(data.user);
    return data.user;
  };

  const register = async (fullName, email, password, confirmPassword = '') => {
    const data = await registerUser(fullName, email, password, confirmPassword);
    saveToken(data.access_token, true);
    setUser(data.user);
    return data.user;
  };

  const updateProfile = async (profileData) => {
    const updated = await updateUserProfile(profileData);
    setUser(updated);
    return updated;
  };

  const changePassword = async (currentPassword, newPassword, confirmPassword = '') => {
    return await changeUserPassword(currentPassword, newPassword, confirmPassword);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        login,
        register,
        logout,
        refreshUser,
        updateProfile,
        changePassword,
        isAuthenticated: !!user,
        isAdmin: user?.role === 'admin',
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
