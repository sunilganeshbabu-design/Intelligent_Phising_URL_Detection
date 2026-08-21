import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import Navbar from './components/Navbar';
import LandingPage from './pages/LandingPage';
import ScannerPage from './pages/ScannerPage';
import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';
import ReportsPage from './pages/ReportsPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import AdminPage from './pages/AdminPage';
import EmailScannerPage from './pages/EmailScannerPage';
import QrScannerPage from './pages/QrScannerPage';
import ThreatLookupPage from './pages/ThreatLookupPage';
import ProfilePage from './pages/ProfilePage';
import BulkScannerModal from './components/BulkScannerModal';
import SecurityChatbot from './components/SecurityChatbot';
import { Lock, ShieldAlert, LogIn, UserPlus } from 'lucide-react';

const PROTECTED_TABS = ['dashboard', 'scanner', 'history', 'reports', 'admin', 'modules', 'profile'];

const ProtectedRouteGuard = ({ targetTab, onNavigateToSignIn, onNavigateToRegister }) => {
  return (
    <div style={{
      minHeight: '70vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px'
    }}>
      <div className="glass-panel" style={{
        maxWidth: '480px',
        width: '100%',
        padding: '36px',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '18px',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6)',
        border: '1px solid rgba(239, 68, 68, 0.3)'
      }}>
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          padding: '16px',
          borderRadius: '50%',
          color: '#EF4444'
        }}>
          <Lock size={36} />
        </div>

        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#F8FAFC' }}>
            Authentication Required
          </h2>
          <p style={{ fontSize: '0.86rem', color: '#94A3B8', marginTop: '6px' }}>
            The <strong>{targetTab.toUpperCase()}</strong> workspace is protected. Please sign in with your email and password to access cybersecurity audits and features.
          </p>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%', marginTop: '4px' }}>
          <button
            onClick={onNavigateToSignIn}
            className="btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '11px' }}
          >
            <LogIn size={16} /> Sign In to Continue
          </button>

          <button
            onClick={onNavigateToRegister}
            className="btn-secondary"
            style={{ width: '100%', justifyContent: 'center', padding: '10px' }}
          >
            <UserPlus size={16} /> Create New Account
          </button>
        </div>
      </div>
    </div>
  );
};

const MainApp = () => {
  const [currentTab, setCurrentTab] = useState('landing');
  const [activeScanUrl, setActiveScanUrl] = useState('');
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
  const [chatbotContext, setChatbotContext] = useState(null);
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const [initialChatbotQuery, setInitialChatbotQuery] = useState('');
  const [redirectAfterLogin, setRedirectAfterLogin] = useState('dashboard');
  const { user, isAuthenticated, isAdmin, loading } = useAuth();

  const handleQuickScan = (url) => {
    setActiveScanUrl(url);
    if (!isAuthenticated) {
      setRedirectAfterLogin('scanner');
      setCurrentTab('login');
    } else {
      setCurrentTab('scanner');
    }
  };

  const handleSetScanContext = (scanResult) => {
    setChatbotContext(scanResult);
    // Explicitly do NOT open chatbot automatically
  };

  const handleOpenChatbotWithContext = (scanResult, autoQuery = false) => {
    setChatbotContext(scanResult);
    if (autoQuery && scanResult?.url) {
      setInitialChatbotQuery(`Why was this URL (${scanResult.url}) classified as ${scanResult.prediction || 'phishing'}?`);
    } else {
      setInitialChatbotQuery('');
    }
    setIsChatbotOpen(true);
  };

  const handleAuthSuccess = () => {
    const target = redirectAfterLogin || 'dashboard';
    setRedirectAfterLogin('dashboard');
    setCurrentTab(target);
  };

  // Enforce Protected Route Guard on tab change
  const isCurrentTabProtected = PROTECTED_TABS.includes(currentTab);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navbar */}
      <Navbar
        onOpenBulkModal={() => {
          if (!isAuthenticated) {
            setRedirectAfterLogin('scanner');
            setCurrentTab('login');
          } else {
            setIsBulkModalOpen(true);
          }
        }}
        currentTab={currentTab}
        setCurrentTab={(tab) => {
          if (PROTECTED_TABS.includes(tab) && !isAuthenticated && !loading) {
            setRedirectAfterLogin(tab);
            setCurrentTab('login');
          } else {
            setCurrentTab(tab);
          }
        }}
      />

      {/* Main Content Body */}
      <main style={{ flex: 1, padding: '24px 0' }}>
        {/* Protected Route Guard Check */}
        {isCurrentTabProtected && !isAuthenticated && !loading ? (
          <ProtectedRouteGuard
            targetTab={currentTab}
            onNavigateToSignIn={() => {
              setRedirectAfterLogin(currentTab);
              setCurrentTab('login');
            }}
            onNavigateToRegister={() => {
              setRedirectAfterLogin(currentTab);
              setCurrentTab('register');
            }}
          />
        ) : (
          <>
            {currentTab === 'landing' && (
              <LandingPage
                setCurrentTab={(tab) => {
                  if (PROTECTED_TABS.includes(tab) && !isAuthenticated) {
                    setRedirectAfterLogin(tab);
                    setCurrentTab('login');
                  } else {
                    setCurrentTab(tab);
                  }
                }}
                onQuickScan={handleQuickScan}
              />
            )}

            {currentTab === 'scanner' && (
              <ScannerPage
                initialUrl={activeScanUrl}
                onSetScanContext={handleSetScanContext}
                onOpenChatbotWithContext={handleOpenChatbotWithContext}
              />
            )}

            {currentTab === 'email_scanner' && (
              <EmailScannerPage />
            )}

            {currentTab === 'qr_scanner' && (
              <QrScannerPage />
            )}

            {currentTab === 'threat_lookup' && (
              <ThreatLookupPage />
            )}

            {currentTab === 'dashboard' && (
              <DashboardPage
                onSelectScan={(url) => {
                  setActiveScanUrl(url);
                  setCurrentTab('scanner');
                }}
                onNavigateModule={(modId, inputVal) => {
                  if (modId === 'email') setCurrentTab('email_scanner');
                  else if (modId === 'qr') setCurrentTab('qr_scanner');
                  else if (modId === 'threat_ioc') setCurrentTab('threat_lookup');
                  else {
                    if (inputVal) setActiveScanUrl(inputVal);
                    setCurrentTab('scanner');
                  }
                }}
              />
            )}

            {currentTab === 'history' && (
              <HistoryPage
                onInspectScan={(url) => {
                  setActiveScanUrl(url);
                  setCurrentTab('scanner');
                }}
              />
            )}

            {currentTab === 'modules' && (
              <ScannerPage
                initialUrl={activeScanUrl}
                initialTab="modules"
                onSetScanContext={handleSetScanContext}
                onOpenChatbotWithContext={handleOpenChatbotWithContext}
              />
            )}

            {currentTab === 'reports' && (
              <ReportsPage />
            )}

            {currentTab === 'login' && (
              <LoginPage
                onLoginSuccess={handleAuthSuccess}
                onNavigateToRegister={() => setCurrentTab('register')}
              />
            )}

            {currentTab === 'register' && (
              <RegisterPage
                onRegisterSuccess={handleAuthSuccess}
                onNavigateToSignIn={() => setCurrentTab('login')}
              />
            )}

            {currentTab === 'profile' && (
              <ProfilePage
                onNavigateScanner={() => setCurrentTab('scanner')}
                onNavigateDashboard={() => setCurrentTab('dashboard')}
              />
            )}

            {currentTab === 'admin' && (
              isAdmin ? (
                <AdminPage />
              ) : (
                <div style={{ textAlign: 'center', padding: '60px 20px', color: '#EF4444' }}>
                  <h2>⚠️ Access Restricted</h2>
                  <p style={{ color: '#94A3B8', marginTop: '8px' }}>
                    You must be logged in as an Administrator to view the Admin Console.
                  </p>
                  <button
                    onClick={() => setCurrentTab('login')}
                    className="btn-primary"
                    style={{ marginTop: '16px' }}
                  >
                    Go to Sign In
                  </button>
                </div>
              )
            )}
          </>
        )}
      </main>

      {/* Bulk Scanner Modal */}
      <BulkScannerModal
        isOpen={isBulkModalOpen}
        onClose={() => setIsBulkModalOpen(false)}
      />

      {/* Floating AI Security Assistant Chatbot */}
      <SecurityChatbot
        currentScanContext={chatbotContext}
        isOpen={isChatbotOpen}
        onOpen={() => setIsChatbotOpen(true)}
        onClose={() => {
          setIsChatbotOpen(false);
          setInitialChatbotQuery('');
        }}
        initialQuery={initialChatbotQuery}
      />

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid rgba(255, 255, 255, 0.08)',
        background: 'rgba(7, 11, 20, 0.9)',
        padding: '24px',
        textAlign: 'center',
        color: '#64748B',
        fontSize: '0.8rem'
      }}>
        <div>
          🛡️ <strong>Intelligent Phishing URL Detection Using Explainable AI (XAI)</strong> • Powered by Scikit-Learn, SHAP, LIME & FastAPI
        </div>
      </footer>
    </div>
  );
};

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <MainApp />
      </AuthProvider>
    </ThemeProvider>
  );
}
