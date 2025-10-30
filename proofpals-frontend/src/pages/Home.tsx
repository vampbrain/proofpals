import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Shield, TrendingUp, MessageSquare, Award, ArrowUp, ArrowDown, Share2, Bookmark, MoreHorizontal, Flame, Clock, Star, Users, Eye, CheckCircle } from 'lucide-react';
import { ThemeToggle } from '@/components/common/ThemeToggle';

// Mock data for Reddit-style posts
const mockPosts = [
  {
    id: 1,
    title: "Zero-Knowledge Proof Implementation in Modern Cryptography",
    author: "u/crypto_researcher",
    community: "r/cryptography",
    time: "3 hours ago",
    upvotes: 2847,
    comments: 156,
    content: "Just completed a comprehensive analysis of zero-knowledge proofs in production systems. The results are fascinating...",
    badges: ["Hot", "Awarded"],
  },
  {
    id: 2,
    title: "Anonymous Peer Review: A Game Changer for Academic Publishing",
    author: "u/academic_reviewer",
    community: "r/academia",
    time: "5 hours ago",
    upvotes: 1923,
    comments: 89,
    content: "Traditional peer review systems have major flaws. Here's how cryptographic anonymity can revolutionize the process...",
    badges: ["Trending"],
  },
  {
    id: 3,
    title: "My Experience with Decentralized Content Verification",
    author: "u/content_creator",
    community: "r/technology",
    time: "8 hours ago",
    upvotes: 1456,
    comments: 234,
    content: "After 6 months using decentralized verification platforms, here are my key takeaways and why you should consider it...",
    badges: [],
  },
  {
    id: 4,
    title: "CLSAG Ring Signatures: The Future of Privacy",
    author: "u/privacy_advocate",
    community: "r/privacy",
    time: "12 hours ago",
    upvotes: 3421,
    comments: 312,
    content: "Deep dive into CLSAG ring signatures and how they're being used to protect user identity in peer review systems...",
    badges: ["Hot", "Gilded"],
  },
  {
    id: 5,
    title: "How Cryptographic Voting Systems Prevent Manipulation",
    author: "u/blockchain_dev",
    community: "r/security",
    time: "1 day ago",
    upvotes: 987,
    comments: 67,
    content: "Exploring various cryptographic voting mechanisms and their applications in content moderation and quality control...",
    badges: [],
  },
];

export function Home() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      {/* Header - Reddit Style */}
      <header className="sticky top-0 z-50 border-b bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-800 shadow-sm">
        <div className="container mx-auto flex h-14 items-center justify-between px-4">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 cursor-pointer" onClick={() => navigate('/')}>
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">ProofPals</h1>
            </div>
            
            {/* Filter Tabs */}
            <nav className="hidden md:flex items-center gap-1">
              <Button variant="ghost" size="sm" className="gap-2 font-semibold">
                <Flame className="h-4 w-4" />
                Hot
              </Button>
              <Button variant="ghost" size="sm" className="gap-2">
                <TrendingUp className="h-4 w-4" />
                Trending
              </Button>
              <Button variant="ghost" size="sm" className="gap-2">
                <Clock className="h-4 w-4" />
                New
              </Button>
              <Button variant="ghost" size="sm" className="gap-2">
                <Star className="h-4 w-4" />
                Top
              </Button>
            </nav>
          </div>
          
          <div className="flex items-center gap-3">
            <ThemeToggle />
            <Button variant="outline" size="sm" onClick={() => navigate('/login')}>
              Log In
            </Button>
            <Button size="sm" onClick={() => navigate('/signup')} className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700">
              Sign Up
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="container mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Main Feed */}
          <div className="lg:col-span-8 space-y-4">
            {/* Create Post Card */}
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-sm">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-full bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
                  <Shield className="h-5 w-5 text-white" />
                </div>
                <input
                  type="text"
                  placeholder="Create Post"
                  className="flex-1 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-900 dark:text-white placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                  onClick={() => navigate('/submitter/upload')}
                  readOnly
                />
              </div>
            </div>

            {/* Posts Feed */}
            {mockPosts.map((post) => (
              <article
                key={post.id}
                className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-hidden hover:border-gray-300 dark:hover:border-gray-700 transition-all shadow-sm hover:shadow-md"
              >
                <div className="flex">
                  {/* Voting Sidebar */}
                  <div className="flex flex-col items-center gap-1 bg-gray-50 dark:bg-gray-800/50 px-3 py-4">
                    <button className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded text-gray-600 dark:text-gray-400 hover:text-orange-500 dark:hover:text-orange-400 transition-colors">
                      <ArrowUp className="h-5 w-5" />
                    </button>
                    <span className="text-sm font-bold text-gray-900 dark:text-white">
                      {post.upvotes >= 1000 ? `${(post.upvotes / 1000).toFixed(1)}k` : post.upvotes}
                    </span>
                    <button className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded text-gray-600 dark:text-gray-400 hover:text-blue-500 dark:hover:text-blue-400 transition-colors">
                      <ArrowDown className="h-5 w-5" />
                    </button>
                  </div>

                  {/* Post Content */}
                  <div className="flex-1 p-4">
                    {/* Post Header */}
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <span className="text-xs font-bold text-gray-900 dark:text-white hover:underline cursor-pointer">
                        {post.community}
                      </span>
                      <span className="text-xs text-gray-500 dark:text-gray-400">•</span>
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        Posted by <span className="hover:underline cursor-pointer">{post.author}</span>
                      </span>
                      <span className="text-xs text-gray-500 dark:text-gray-400">{post.time}</span>
                      {post.badges.map((badge) => (
                        <Badge
                          key={badge}
                          variant="secondary"
                          className={`text-xs px-2 py-0 ${
                            badge === 'Hot' ? 'bg-orange-100 dark:bg-orange-950 text-orange-700 dark:text-orange-300' :
                            badge === 'Trending' ? 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300' :
                            'bg-yellow-100 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300'
                          }`}
                        >
                          {badge}
                        </Badge>
                      ))}
                    </div>

                    {/* Post Title */}
                    <h2 className="text-lg font-bold text-gray-900 dark:text-white mb-2 hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer line-clamp-2">
                      {post.title}
                    </h2>

                    {/* Post Preview */}
                    <p className="text-sm text-gray-700 dark:text-gray-300 mb-3 line-clamp-2">
                      {post.content}
                    </p>

                    {/* Post Actions */}
                    <div className="flex items-center gap-4 text-gray-600 dark:text-gray-400">
                      <button className="flex items-center gap-1 px-3 py-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-sm">
                        <MessageSquare className="h-4 w-4" />
                        <span>{post.comments} Comments</span>
                      </button>
                      <button className="flex items-center gap-1 px-3 py-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-sm">
                        <Share2 className="h-4 w-4" />
                        <span>Share</span>
                      </button>
                      <button className="flex items-center gap-1 px-3 py-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-sm">
                        <Bookmark className="h-4 w-4" />
                        <span>Save</span>
                      </button>
                      <button className="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors">
                        <MoreHorizontal className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              </article>
            ))}
          </div>

          {/* Sidebar */}
          <aside className="hidden lg:block lg:col-span-4 space-y-4">
            {/* About ProofPals */}
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-hidden shadow-sm">
              <div className="bg-gradient-to-r from-blue-600 to-indigo-600 h-16"></div>
              <div className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                  <h3 className="font-bold text-gray-900 dark:text-white">About ProofPals</h3>
                </div>
                <p className="text-sm text-gray-700 dark:text-gray-300 mb-4">
                  A decentralized anonymous peer review platform powered by zero-knowledge cryptography and CLSAG ring signatures.
                </p>
                <div className="space-y-2 mb-4">
                  <div className="flex items-center gap-2 text-sm">
                    <Users className="h-4 w-4 text-gray-500" />
                    <span className="text-gray-700 dark:text-gray-300">12.5k Members</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <Eye className="h-4 w-4 text-gray-500" />
                    <span className="text-gray-700 dark:text-gray-300">2.1k Online</span>
                  </div>
                </div>
                <Button 
                  onClick={() => navigate('/signup')} 
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                >
                  Join Community
                </Button>
              </div>
            </div>

            {/* Features */}
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-sm">
              <h3 className="font-bold text-gray-900 dark:text-white mb-3">Platform Features</h3>
              <div className="space-y-3">
                <div className="flex items-start gap-2">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">Anonymous Review</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">Complete identity protection</p>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">Cryptographic Proofs</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">Zero-knowledge verification</p>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">Weighted Voting</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">Fair quality control</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Resources */}
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-sm">
              <h3 className="font-bold text-gray-900 dark:text-white mb-3">Resources</h3>
              <div className="space-y-2">
                <a href="#" className="block text-sm text-blue-600 dark:text-blue-400 hover:underline">Documentation</a>
                <a href="#" className="block text-sm text-blue-600 dark:text-blue-400 hover:underline">API Reference</a>
                <a href="#" className="block text-sm text-blue-600 dark:text-blue-400 hover:underline">Community Guidelines</a>
                <a href="#" className="block text-sm text-blue-600 dark:text-blue-400 hover:underline">Privacy Policy</a>
              </div>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
