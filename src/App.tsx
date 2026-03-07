import React, { useState } from "react";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import AdminDashboard from "./pages/AdminDashboard";
import { AuditProvider, SecurityAuditPanel } from "./components/SecurityAuditPanel";

type AppView = 'user-login' | 'user-dashboard' | 'admin-dashboard';

export default function App() {
  const [view, setView]             = useState<AppView>('user-login');
  const [user, setUser]             = useState<string | null>(null);
  const [adminToken, setAdminToken] = useState<string | null>(null);
  const [stepUpPending, setStepUpPending] = useState<string | null>(null);

  // Regular user login success
  const handleLoginSuccess = (username: string) => {
    setUser(username);
    setView('user-dashboard');
  };

  // Admin login success
  const handleAdminSuccess = (token: string) => {
    setAdminToken(token);
    setView('admin-dashboard');
  };

  // Step-up: send user back to login, remember pending operation
  const handleStepUp = (operationId: string) => {
    setStepUpPending(operationId);
    setUser(null);
    setView('user-login');
  };

  // Logout from any view
  const handleLogout = () => {
    setUser(null);
    setAdminToken(null);
    setStepUpPending(null);
    setView('user-login');
  };

  return (
    <AuditProvider>

      {view === 'user-login' && (
        <Login
          onLoginSuccess={handleLoginSuccess}
          onAdminSuccess={handleAdminSuccess}
          stepUpOperation={stepUpPending}
        />
      )}

      {view === 'user-dashboard' && user && (
        <Dashboard
          user={user}
          onNavigate={() => {}}
          onStepUp={handleStepUp}
          pendingOperation={stepUpPending}
          onStepUpComplete={() => setStepUpPending(null)}
        />
      )}

      {view === 'admin-dashboard' && adminToken && (
        <AdminDashboard
          token={adminToken}
          onLogout={handleLogout}
        />
      )}

      {/* Audit panel only for user flows, not admin console */}
      {view !== 'admin-dashboard' && <SecurityAuditPanel />}

    </AuditProvider>
  );
}