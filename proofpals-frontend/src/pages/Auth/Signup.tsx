import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useNavigate, Link } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Shield, UserPlus, CheckCircle2 } from 'lucide-react';
import { toast } from 'sonner';
import { ThemeToggle } from '@/components/common/ThemeToggle';

const signupSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username must be less than 50 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
  email: z.string().email('Please enter a valid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password must be less than 100 characters')
    .refine((password) => /[A-Z]/.test(password), 'Password must contain at least one uppercase letter')
    .refine((password) => /[a-z]/.test(password), 'Password must contain at least one lowercase letter')
    .refine((password) => /\d/.test(password), 'Password must contain at least one number'),
  confirmPassword: z.string(),
  role: z.enum(['submitter', 'reviewer'], {
    required_error: 'Please select a role',
  }),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type SignupFormData = z.infer<typeof signupSchema>;

export function Signup() {
  const navigate = useNavigate();
  const { signup } = useAuthStore();
  const [isLoading, setIsLoading] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
  } = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
  });

  const watchedRole = watch('role');

  const onSubmit = async (data: SignupFormData) => {
    setIsLoading(true);
    try {
      await signup({
        username: data.username,
        email: data.email,
        password: data.password,
        role: data.role,
      });
      toast.success('Account created successfully!');
      if (data.role === 'reviewer') {
        navigate('/reviewer/dashboard');
      } else {
        navigate('/submitter/submissions');
      }
    } catch (error: any) {
      toast.error(error.message || 'Signup failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-background">
      {/* Theme Toggle - Fixed Position */}
      <div className="fixed top-6 right-6 z-50">
        <ThemeToggle />
      </div>

      {/* Left Side - Branding */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-emerald-600 via-green-600 to-teal-700 dark:from-emerald-900 dark:via-green-900 dark:to-teal-900 items-center justify-center p-12 relative overflow-hidden">
        {/* Animated Background Elements */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-1/2 -left-1/2 w-full h-full bg-white/5 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute -bottom-1/2 -right-1/2 w-full h-full bg-white/5 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
        </div>

        <div className="text-center text-white max-w-md relative z-10">
          <div className="mb-8 animate-fade-in">
            <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-3xl bg-white/20 backdrop-blur-lg mb-6 shadow-2xl border border-white/30">
              <UserPlus className="h-10 w-10 text-white drop-shadow-lg" />
            </div>
            <h1 className="text-5xl font-bold mb-3 tracking-tight">Join ProofPals</h1>
            <div className="h-1 w-20 bg-gradient-to-r from-transparent via-white/60 to-transparent mx-auto rounded-full mb-6"></div>
          </div>
          <p className="text-xl font-light text-white/95 leading-relaxed mb-8 animate-slide-in">
            Become part of our anonymous peer review community
          </p>
          <div className="space-y-4 text-left max-w-xs mx-auto animate-slide-in" style={{ animationDelay: '0.2s' }}>
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-white/90 flex-shrink-0" />
              <span className="text-sm text-white/90">Complete anonymity guaranteed</span>
            </div>
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-white/90 flex-shrink-0" />
              <span className="text-sm text-white/90">Cryptographic identity protection</span>
            </div>
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-white/90 flex-shrink-0" />
              <span className="text-sm text-white/90">Fair weighted voting system</span>
            </div>
          </div>
        </div>
      </div>

      {/* Right Side - Signup Form */}
      <div className="flex-1 flex items-center justify-center p-8 bg-gray-50 dark:bg-gray-950 overflow-y-auto">
        <div className="w-full max-w-md py-8">
          {/* Mobile Logo */}
          <div className="lg:hidden text-center mb-8 animate-fade-in">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-500 to-green-600 dark:from-emerald-600 dark:to-green-700 mb-4 shadow-lg">
              <UserPlus className="h-8 w-8 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Join ProofPals</h1>
          </div>

          {/* Signup Card */}
          <div className="bg-white dark:bg-gray-900 rounded-3xl shadow-2xl border border-gray-200 dark:border-gray-800 p-8 animate-scale-in">
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">Create Account</h2>
              <p className="text-gray-600 dark:text-gray-400">Start your secure review journey</p>
            </div>

            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
              <div>
                <Label htmlFor="username" className="text-sm font-semibold text-gray-700 dark:text-gray-300 block mb-3">
                  Username
                </Label>
                <Input
                  id="username"
                  placeholder="Choose a unique username"
                  {...register('username')}
                  className="h-12 rounded-xl border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 focus:bg-white dark:focus:bg-gray-900 focus:border-emerald-500 dark:focus:border-emerald-600 transition-all text-gray-900 dark:text-white placeholder:text-gray-500 dark:placeholder:text-gray-500"
                />
                {errors.username && (
                  <p className="text-sm text-red-500 dark:text-red-400 mt-2">{errors.username.message}</p>
                )}
              </div>

              <div>
                <Label htmlFor="email" className="text-sm font-semibold text-gray-700 dark:text-gray-300 block mb-3">
                  Email
                </Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="your.email@example.com"
                  {...register('email')}
                  className="h-12 rounded-xl border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 focus:bg-white dark:focus:bg-gray-900 focus:border-emerald-500 dark:focus:border-emerald-600 transition-all text-gray-900 dark:text-white placeholder:text-gray-500 dark:placeholder:text-gray-500"
                />
                {errors.email && (
                  <p className="text-sm text-red-500 dark:text-red-400 mt-2">{errors.email.message}</p>
                )}
              </div>

              <div>
                <Label htmlFor="role" className="text-sm font-semibold text-gray-700 dark:text-gray-300 block mb-3">
                  Role
                </Label>
                <Select
                  value={watchedRole}
                  onValueChange={(value) => setValue('role', value as 'submitter' | 'reviewer')}
                >
                  <SelectTrigger className="h-12 rounded-xl border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 focus:bg-white dark:focus:bg-gray-900 focus:border-emerald-500 dark:focus:border-emerald-600 text-gray-900 dark:text-white transition-all">
                    <SelectValue placeholder="Select your role" className="text-gray-500 dark:text-gray-400" />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-xl">
                    <SelectItem value="submitter" className="rounded-lg text-gray-900 dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700 focus:bg-gray-100 dark:focus:bg-gray-700">
                      Content Submitter
                    </SelectItem>
                    <SelectItem value="reviewer" className="rounded-lg text-gray-900 dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700 focus:bg-gray-100 dark:focus:bg-gray-700">
                      Content Reviewer
                    </SelectItem>
                  </SelectContent>
                </Select>
                {errors.role && (
                  <p className="text-sm text-red-500 dark:text-red-400 mt-2">{errors.role.message}</p>
                )}
              </div>

              <div>
                <Label htmlFor="password" className="text-sm font-semibold text-gray-700 dark:text-gray-300 block mb-3">
                  Password
                </Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Create a strong password"
                  {...register('password')}
                  className="h-12 rounded-xl border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 focus:bg-white dark:focus:bg-gray-900 focus:border-emerald-500 dark:focus:border-emerald-600 transition-all text-gray-900 dark:text-white placeholder:text-gray-500 dark:placeholder:text-gray-500"
                />
                {errors.password && (
                  <p className="text-sm text-red-500 dark:text-red-400 mt-2">{errors.password.message}</p>
                )}
              </div>

              <div>
                <Label htmlFor="confirmPassword" className="text-sm font-semibold text-gray-700 dark:text-gray-300 block mb-3">
                  Confirm Password
                </Label>
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="Confirm your password"
                  {...register('confirmPassword')}
                  className="h-12 rounded-xl border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 focus:bg-white dark:focus:bg-gray-900 focus:border-emerald-500 dark:focus:border-emerald-600 transition-all text-gray-900 dark:text-white placeholder:text-gray-500 dark:placeholder:text-gray-500"
                />
                {errors.confirmPassword && (
                  <p className="text-sm text-red-500 dark:text-red-400 mt-2">{errors.confirmPassword.message}</p>
                )}
              </div>

              <div className="p-4 bg-emerald-50 dark:bg-emerald-950/30 rounded-xl border border-emerald-200 dark:border-emerald-900/50">
                <div className="flex items-start gap-3">
                  <Shield className="h-5 w-5 text-emerald-600 dark:text-emerald-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-semibold text-emerald-900 dark:text-emerald-300 mb-1">Privacy Protected</p>
                    <p className="text-xs text-emerald-700 dark:text-emerald-400">
                      Your identity is protected by cryptographic proofs
                    </p>
                  </div>
                </div>
              </div>

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full h-12 rounded-xl bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-700 hover:to-green-700 dark:from-emerald-500 dark:to-green-500 dark:hover:from-emerald-600 dark:hover:to-green-600 text-white font-semibold shadow-lg hover:shadow-xl transition-all duration-200 disabled:opacity-50"
              >
                {isLoading ? (
                  <div className="flex items-center gap-2">
                    <div className="h-5 w-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    Creating Account...
                  </div>
                ) : (
                  'Create Account'
                )}
              </Button>
            </form>

            <div className="mt-8 text-center">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Already have an account?{' '}
                <Link 
                  to="/login"
                  className="text-emerald-600 dark:text-emerald-400 hover:text-emerald-700 dark:hover:text-emerald-300 font-semibold transition-colors"
                >
                  Sign in
                </Link>
              </p>
            </div>
          </div>

          {/* Footer */}
          <p className="text-center text-xs text-gray-500 dark:text-gray-500 mt-8">
            Protected by zero-knowledge cryptography
          </p>
        </div>
      </div>
    </div>
  );
}
