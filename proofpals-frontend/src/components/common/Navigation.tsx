import { useNavigate, useLocation } from 'react-router-dom';
import { cn } from '@/lib/utils/formatting';
import { FileText, Users, Shield, BarChart3, KeyRound, Home, Sparkles } from 'lucide-react';

interface NavItem {
  label: string;
  path: string;
  icon: React.ElementType;
}

interface NavigationProps {
  role: 'submitter' | 'reviewer' | 'admin';
}

const navItems: Record<NavigationProps['role'], NavItem[]> = {
  submitter: [
    { label: 'Home', path: '/', icon: Home },
    { label: 'My Submissions', path: '/submitter/submissions', icon: FileText },
    { label: 'Upload', path: '/submitter/upload', icon: FileText },
  ],
  reviewer: [
    { label: 'Home', path: '/', icon: Home },
    { label: 'Dashboard', path: '/reviewer/dashboard', icon: Shield },
    { label: 'Submissions', path: '/reviewer/submissions', icon: FileText },
    { label: 'Upload', path: '/reviewer/upload', icon: FileText },
    { label: 'Get Tokens', path: '/reviewer/tokens', icon: KeyRound },
  ],
  admin: [
    { label: 'Home', path: '/', icon: Home },
    { label: 'Dashboard', path: '/admin/dashboard', icon: BarChart3 },
    { label: 'Rings', path: '/admin/rings', icon: Shield },
    { label: 'Escalations', path: '/admin/escalations', icon: Shield },
    { label: 'Credential Allocation', path: '/admin/credentials', icon: KeyRound },
    { label: 'Audit Logs', path: '/admin/audit-logs', icon: FileText },
    { label: 'Statistics', path: '/admin/statistics', icon: BarChart3 },
  ],
};

export function Navigation({ role }: NavigationProps) {
  const navigate = useNavigate();
  const location = useLocation();

  const items = navItems[role] || [];

  return (
    <nav className="w-72 border-r border-border/40 bg-background/95 backdrop-blur-md supports-[backdrop-filter]:bg-background/60 p-6">
      {/* Brand */}
      <div className="mb-10 animate-fade-in">
        <div className="flex items-center gap-3 mb-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-blue-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-soft">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-foreground tracking-tight">ProofPals</h2>
          </div>
        </div>
        <div className="flex items-center gap-2 pl-1">
          <div className="h-1.5 w-1.5 rounded-full bg-primary"></div>
          <p className="text-xs text-muted-foreground font-medium capitalize tracking-wide">{role} Portal</p>
        </div>
      </div>

      {/* Navigation Items */}
      <div className="space-y-1.5">
        {items.map((item, index) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;

          return (
            <button
              key={item.path}
              onClick={() => navigate(item.path)}
              className={cn(
                'group flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left text-sm font-medium transition-smooth hover-lift',
                'animate-slide-in',
                `stagger-${Math.min(index + 1, 5)}`,
                isActive
                  ? 'bg-gradient-to-r from-primary/10 via-primary/5 to-transparent text-primary shadow-soft border border-primary/20'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
              )}
            >
              <div className={cn(
                "relative flex items-center justify-center",
                isActive && "animate-scale-in"
              )}>
                <Icon className={cn(
                  "h-5 w-5 transition-transform group-hover:scale-110",
                  isActive ? "text-primary" : "text-muted-foreground/60 group-hover:text-foreground"
                )} />
                {isActive && (
                  <div className="absolute inset-0 rounded-lg bg-primary/20 blur-md -z-10"></div>
                )}
              </div>
              <span className="truncate flex-1">{item.label}</span>
              {isActive && (
                <div className="flex items-center gap-1">
                  <div className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse"></div>
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Footer decoration */}
      <div className="mt-10 pt-6 border-t border-border/40">
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-muted/30 border border-border/30">
          <Sparkles className="h-4 w-4 text-primary/60" />
          <p className="text-xs text-muted-foreground">
            Anonymous & Secure
          </p>
        </div>
      </div>
    </nav>
  );
}
