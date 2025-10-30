import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/ui/button';
import { Shield, LogOut, User } from 'lucide-react';

export function Header() {
  const navigate = useNavigate();
  const { user, isAuthenticated, logout } = useAuthStore();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="sticky top-0 z-50 border-b border-border/40 bg-background/95 backdrop-blur-md supports-[backdrop-filter]:bg-background/60">
      <div className="flex h-16 items-center justify-end px-6 lg:px-8">
        {isAuthenticated && (
          <div className="flex items-center gap-4 animate-fade-in">
            <div className="flex items-center gap-3 px-4 py-2 rounded-full bg-muted/50 border border-border/50 hover:bg-muted/80 transition-smooth">
              <div className="relative">
                <div className="h-9 w-9 rounded-full bg-gradient-to-br from-blue-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-soft">
                  <span className="text-sm font-semibold text-white">
                    {user?.username?.charAt(0).toUpperCase()}
                  </span>
                </div>
                <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-green-500 border-2 border-background"></div>
              </div>
              <div className="hidden sm:block">
                <p className="text-sm font-medium text-foreground leading-none">
                  {user?.username}
                </p>
                <p className="text-xs text-muted-foreground capitalize mt-1">
                  {user?.role}
                </p>
              </div>
            </div>
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={handleLogout}
              className="h-10 w-10 rounded-full hover:bg-destructive/10 hover:text-destructive transition-smooth group"
            >
              <LogOut className="h-4 w-4 group-hover:scale-110 transition-transform" />
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
