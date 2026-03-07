
// import React, { useState } from 'react';
// import Login from './pages/Login.tsx';
// import Dashboard from './pages/Dashboard';
// import SecureOperation from './pages/SecureOperation';
// import AuditLogs from './pages/AuditLogs';
// import IntegrityCheck from './pages/IntegrityCheck';
// import { OperationType } from './types';
// import { Shield, LogOut, Info } from 'lucide-react';
// import { UI_STRINGS } from './constants';

// const App: React.FC = () => {
//   const [currentUser, setCurrentUser] = useState<string | null>(null);
//   const [currentPage, setCurrentPage] = useState<string>('dashboard');
//   const [pageParams, setPageParams] = useState<any>({});

//   const handleLogin = (username: string) => {
//     setCurrentUser(username);
//     setCurrentPage('dashboard');
//   };

//   const handleLogout = () => {
//     setCurrentUser(null);
//     setCurrentPage('dashboard');
//   };

//   const navigate = (page: string, params: any = {}) => {
//     setCurrentPage(page);
//     setPageParams(params);
//   };

//   // if (!currentUser) {
//   //   return <Login onLoginSuccess={handleLogin} />;
//   // }
//   if (!currentUser) {
//   return <div>LOGIN PAGE LOADING...</div>;
// }

//   return (
//     <div className="min-h-screen bg-slate-50 flex flex-col">
//       {/* Top Academic Banner */}
//       <div className="bg-blue-600 text-white py-2 px-4 flex items-center justify-between text-[10px] font-bold uppercase tracking-widest">
//         <div className="flex items-center gap-2">
//           <Info size={12} />
//           {UI_STRINGS.BANNER}
//         </div>
//         <div>{UI_STRINGS.DISCLAIMER}</div>
//       </div>

//       {/* Main Navigation */}
//       <nav className="bg-white border-b border-slate-200 sticky top-0 z-40">
//         <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
//           <button 
//             onClick={() => navigate('dashboard')}
//             className="flex items-center gap-2 text-slate-900 group"
//           >
//             <div className="bg-slate-900 p-1.5 rounded-lg text-white group-hover:bg-blue-600 transition-colors">
//               <Shield size={20} />
//             </div>
//             <span className="font-bold text-lg">SecureBank</span>
//           </button>

//           <div className="flex items-center gap-6">
//             <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-slate-50 border border-slate-100 rounded-full">
//               <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
//               <span className="text-xs font-bold text-slate-600 uppercase tracking-wider">{currentUser}</span>
//             </div>
//             <button 
//               onClick={handleLogout}
//               className="p-2 text-slate-400 hover:text-rose-600 transition-colors"
//               title="Logout"
//             >
//               <LogOut size={20} />
//             </button>
//           </div>
//         </div>
//       </nav>

//       {/* Main Content Area */}
//       <main className="flex-1 max-w-7xl mx-auto px-4 py-8 w-full">
//         {currentPage === 'dashboard' && (
//           <Dashboard user={currentUser} onNavigate={navigate} />
//         )}
        
//         {currentPage === 'operation' && (
//           <SecureOperation 
//             type={pageParams.type} 
//             username={currentUser} 
//             onBack={() => navigate('dashboard')} 
//           />
//         )}

//         {currentPage === 'logs' && (
//           <AuditLogs onBack={() => navigate('dashboard')} />
//         )}

//         {currentPage === 'integrity' && (
//           <IntegrityCheck onBack={() => navigate('dashboard')} />
//         )}
//       </main>

//       {/* Footer */}
//       <footer className="bg-white border-t border-slate-200 py-8 px-4 mt-12">
//         <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4 text-slate-400 text-[10px] font-bold uppercase tracking-widest">
//           <p>© 2025 Academic Demo • Cryptography & Secure Systems Lab</p>
//           <div className="flex gap-6">
//             <span className="hover:text-slate-600 cursor-pointer">Security Protocol v4.1</span>
//             <span className="hover:text-slate-600 cursor-pointer">Context-Aware Nonce Demo</span>
//             <span className="hover:text-slate-600 cursor-pointer">Risk Policy Engine v1.0</span>
//           </div>
//         </div>
//       </footer>
//     </div>
//   );
// };

// export default App;

// import React, { useState } from "react";
// import Login from "./pages/Login";
// import Dashboard from "./pages/Dashboard";

// export default function App() {
//   const [user, setUser] = useState<string | null>(null);

//   if (!user) {
//     return <Login onLoginSuccess={setUser} />;
//   }

//   return <Dashboard user={user} onNavigate={() => {}} />;
// }

import React, { useState } from 'react';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import { AuditProvider, SecurityAuditPanel } from './components/SecurityAuditPanel';

export default function App() {
  const [user, setUser] = useState<string | null>(null);

  return (
    <AuditProvider>
      {!user
        ? <Login onLoginSuccess={setUser} />
        : <Dashboard user={user} onNavigate={() => {}} />
      }
      {/* Floating audit panel — visible on every page */}
      <SecurityAuditPanel />
    </AuditProvider>
  );
}
