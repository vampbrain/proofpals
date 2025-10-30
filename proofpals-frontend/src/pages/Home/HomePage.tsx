// src/pages/Home/HomePage.tsx
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { Search, Filter, Calendar, CheckCircle, Eye, Shield } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { ContentViewer } from '@/components/submission/ContentViewer';
import { useAuthStore } from '@/store/authStore';
import { cn } from '@/lib/utils/formatting';

const GENRES = [
  { value: 'all', label: 'All Genres' },
  { value: 'news', label: 'News & Journalism' },
  { value: 'research', label: 'Research & Academia' },
  { value: 'music', label: 'Music & Audio' },
  { value: 'video', label: 'Video & Film' },
  { value: 'literature', label: 'Literature & Writing' },
  { value: 'art', label: 'Art & Visual Media' },
];

export function HomePage() {
  const { user } = useAuthStore();
  
  // Debug: log user state
  console.log('HomePage - Current user:', user);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedGenre, setSelectedGenre] = useState('all');
  const [expandedCard, setExpandedCard] = useState<number | null>(null);

  const { data: approvedSubmissions, isLoading } = useQuery<any>({
    queryKey: ['approved-submissions', selectedGenre, searchTerm],
    queryFn: () => apiClient.get('/api/v1/submissions/approved?limit=50'),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const filteredSubmissions = approvedSubmissions?.submissions?.filter((submission: any) => {
    const matchesGenre = selectedGenre === 'all' || submission.genre === selectedGenre;
    const matchesSearch = searchTerm === '' || 
      submission.content_ref.toLowerCase().includes(searchTerm.toLowerCase()) ||
      submission.genre.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesGenre && matchesSearch;
  }) || [];

  if (isLoading) return <Loading />;

  return (
    <div className="flex min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
      {user && <Navigation role={user.role as 'admin' | 'reviewer' | 'submitter'} />}
      <div className="flex-1">
        {user && <Header />}
        <main className="container mx-auto px-4 sm:px-6 lg:px-8 py-12 max-w-7xl">
          {/* Hero Section */}
          <div className="mb-16 text-center animate-fade-in">
            <div className="mb-8">
              <div className="inline-flex items-center gap-2 px-4 py-2 mb-6 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium">
                <Shield className="h-4 w-4" />
                <span>Verified Community</span>
              </div>
              <h1 className="mb-4 text-6xl font-extralight text-foreground tracking-tight">
                Proof<span className="text-gradient font-normal">Pals</span>
              </h1>
              <div className="h-1 w-20 bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-500 mx-auto rounded-full mb-6"></div>
            </div>
            <p className="mx-auto max-w-2xl text-xl text-muted-foreground font-light leading-relaxed">
              Discover quality content verified by our anonymous community of reviewers
            </p>
          </div>

          {/* Stats Section */}
          <div className="mb-16 grid gap-6 md:grid-cols-3 animate-fade-in">
            <div className="group text-center p-8 rounded-2xl bg-card border border-border hover:border-primary/30 shadow-soft hover:shadow-soft-lg transition-smooth hover-lift">
              <div className="mx-auto mb-4 h-14 w-14 rounded-2xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center shadow-soft group-hover:scale-110 transition-transform">
                <CheckCircle className="h-7 w-7 text-white" />
              </div>
              <p className="text-4xl font-extralight text-foreground mb-2">{filteredSubmissions.length}</p>
              <p className="text-sm text-muted-foreground font-medium">Approved Content</p>
            </div>
            <div className="group text-center p-8 rounded-2xl bg-card border border-border hover:border-primary/30 shadow-soft hover:shadow-soft-lg transition-smooth hover-lift">
              <div className="mx-auto mb-4 h-14 w-14 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-soft group-hover:scale-110 transition-transform">
                <Eye className="h-7 w-7 text-white" />
              </div>
              <p className="text-4xl font-extralight text-foreground mb-2">{GENRES.length - 1}</p>
              <p className="text-sm text-muted-foreground font-medium">Categories</p>
            </div>
            <div className="group text-center p-8 rounded-2xl bg-card border border-border hover:border-primary/30 shadow-soft hover:shadow-soft-lg transition-smooth hover-lift">
              <div className="mx-auto mb-4 h-14 w-14 rounded-2xl bg-gradient-to-br from-purple-500 to-violet-600 flex items-center justify-center shadow-soft group-hover:scale-110 transition-transform">
                <Calendar className="h-7 w-7 text-white" />
              </div>
              <p className="text-4xl font-extralight text-foreground mb-2">24/7</p>
              <p className="text-sm text-muted-foreground font-medium">Community Review</p>
            </div>
          </div>

          {/* Filters */}
          <div className="mb-12 flex flex-col sm:flex-row gap-4 items-center justify-center animate-fade-in">
            <div className="relative group">
              <Search className="absolute left-5 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground/50 group-hover:text-primary transition-colors" />
              <Input
                placeholder="Search content..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-14 pr-6 py-6 w-96 rounded-2xl border-border bg-card shadow-soft focus:shadow-soft-lg focus:border-primary/50 transition-smooth text-base"
              />
            </div>
            <Select value={selectedGenre} onValueChange={setSelectedGenre}>
              <SelectTrigger className="w-56 h-14 rounded-2xl border-border bg-card shadow-soft hover:shadow-soft-lg focus:border-primary/50 transition-smooth text-base text-foreground">
                <Filter className="h-4 w-4 mr-2 text-muted-foreground" />
                <SelectValue placeholder="All Categories" className="text-muted-foreground" />
              </SelectTrigger>
              <SelectContent className="rounded-xl border-border bg-card shadow-xl">
                {GENRES.map((genre) => (
                  <SelectItem 
                    key={genre.value} 
                    value={genre.value}
                    className="rounded-lg text-foreground hover:bg-muted focus:bg-muted transition-colors"
                  >
                    {genre.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Content Grid */}
          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3 animate-fade-in">
            {filteredSubmissions.map((submission: any, index: number) => (
              <div 
                key={submission.id} 
                className={cn(
                  "group relative overflow-hidden rounded-3xl bg-card border border-border hover:border-primary/30 shadow-soft hover:shadow-soft-lg transition-smooth hover-lift",
                  "animate-scale-in",
                  `stagger-${Math.min((index % 3) + 1, 5)}`
                )}
              >
                {/* Status Badge */}
                <div className="absolute top-5 right-5 z-10">
                  <div className="flex items-center gap-1.5 px-3 py-1.5 bg-green-500/10 backdrop-blur-sm border border-green-500/20 text-green-700 rounded-full text-xs font-medium shadow-soft">
                    <CheckCircle className="h-3.5 w-3.5" />
                    <span>Verified</span>
                  </div>
                </div>

                <div className="p-7">
                  {/* Header */}
                  <div className="mb-5">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="h-2 w-2 rounded-full bg-primary animate-pulse"></div>
                      <span className="text-xs font-semibold text-primary uppercase tracking-wider">
                        {submission.genre}
                      </span>
                    </div>
                    <h3 className="text-xl font-semibold text-foreground mb-2 group-hover:text-primary transition-colors">
                      Content #{submission.id}
                    </h3>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Calendar className="h-3.5 w-3.5" />
                      <span>
                        {new Date(submission.approved_at || submission.created_at).toLocaleDateString('en-US', { 
                          month: 'short', 
                          day: 'numeric', 
                          year: 'numeric' 
                        })}
                      </span>
                    </div>
                  </div>

                  {/* Content Preview */}
                  <div className="mb-5">
                    <div className="p-4 rounded-xl bg-muted/30 border border-border/50">
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {submission.content_ref}
                      </p>
                    </div>
                  </div>

                  {/* Expanded Content */}
                  {expandedCard === submission.id && (
                    <div className="mb-5 p-5 bg-muted/30 rounded-2xl border border-border animate-scale-in">
                      <ContentViewer contentRef={submission.content_ref} />
                    </div>
                  )}

                  {/* Action Button */}
                  <Button
                    variant={expandedCard === submission.id ? "outline" : "default"}
                    size="lg"
                    onClick={() => setExpandedCard(expandedCard === submission.id ? null : submission.id)}
                    className={cn(
                      "w-full rounded-xl font-medium transition-smooth group/btn",
                      expandedCard === submission.id 
                        ? "bg-muted hover:bg-muted/80 text-foreground border-border" 
                        : "bg-gradient-to-r from-blue-500 via-blue-600 to-indigo-600 hover:from-blue-600 hover:via-blue-700 hover:to-indigo-700 text-white shadow-soft hover:shadow-soft-lg"
                    )}
                  >
                    <Eye className="mr-2 h-4 w-4 group-hover/btn:scale-110 transition-transform" />
                    {expandedCard === submission.id ? 'Show Less' : 'View Content'}
                  </Button>
                </div>
              </div>
            ))}
          </div>

          {filteredSubmissions.length === 0 && (
            <div className="py-20 text-center animate-fade-in">
              <div className="mx-auto mb-6 h-20 w-20 rounded-3xl bg-muted/50 flex items-center justify-center border border-border">
                <Search className="h-10 w-10 text-muted-foreground/50" />
              </div>
              <h3 className="mb-3 text-2xl font-semibold text-foreground">No content found</h3>
              <p className="text-muted-foreground text-lg max-w-md mx-auto">
                {searchTerm || selectedGenre !== 'all' 
                  ? 'Try adjusting your search or filter criteria.'
                  : 'No approved content available yet. Check back later!'}
              </p>
            </div>
          )}

          {/* Footer Info */}
          <div className="mt-24 py-16 text-center border-t border-border/50 animate-fade-in">
            <div className="max-w-3xl mx-auto">
              <div className="mb-6 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20">
                <Shield className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium text-primary">Trusted Community</span>
              </div>
              <h3 className="mb-6 text-3xl font-light text-foreground">Anonymous. Verified. Trusted.</h3>
              <p className="text-muted-foreground text-lg leading-relaxed">
                Every piece of content here has been anonymously reviewed and verified by our 
                decentralized community of experts, ensuring quality while protecting privacy.
              </p>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
