// src/hooks/useAuth.ts
import { useState, useEffect } from 'react';

interface User {
  id: number;
  username: string;
  role: 'admin' | 'reviewer' | 'submitter';
}

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // For now, we'll use a simple localStorage-based auth
    // In production, this would check with the backend
    const storedUser = localStorage.getItem('proofpals_user');
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (error) {
        console.error('Error parsing stored user:', error);
        localStorage.removeItem('proofpals_user');
      }
    }
    setIsLoading(false);
  }, []);

  const login = (userData: User) => {
    setUser(userData);
    localStorage.setItem('proofpals_user', JSON.stringify(userData));
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('proofpals_user');
  };

  return {
    user,
    isLoading,
    login,
    logout,
    isAuthenticated: !!user,
  };
}