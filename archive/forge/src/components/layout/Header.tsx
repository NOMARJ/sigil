'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter, usePathname } from 'next/navigation';
import { 
  MagnifyingGlassIcon, 
  Bars3Icon, 
  XMarkIcon,
  ShieldCheckIcon,
  CubeIcon
} from '@heroicons/react/24/outline';
import { Button } from '@/components/ui/Button';
import { SearchInput } from '@/components/ui/Search';
import { cn } from '@/lib/utils';

const navigation = [
  { name: 'Discover', href: '/discover' },
  { name: 'Stacks', href: '/stacks' },
  { name: 'Categories', href: '/categories' },
  { name: 'Publishers', href: '/publishers' },
  { name: 'Docs', href: '/docs' },
];

export function Header() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 10);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleSearch = (query: string) => {
    if (query.trim()) {
      router.push(`/discover?q=${encodeURIComponent(query)}`);
      setSearchOpen(false);
    }
  };

  return (
    <header className={cn(
      'sticky top-0 z-50 bg-white border-b border-gray-200 transition-all duration-200',
      scrolled && 'shadow-md'
    )}>
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <div className="flex items-center">
            <Link href="/" className="flex items-center space-x-2 group">
              <div className="relative">
                <ShieldCheckIcon className="h-8 w-8 text-sigil-600 transition-colors group-hover:text-sigil-700" />
                <CubeIcon className="h-4 w-4 text-sigil-400 absolute -top-1 -right-1" />
              </div>
              <span className="text-xl font-bold text-gray-900">
                Sigil <span className="text-sigil-600">Forge</span>
              </span>
            </Link>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            {navigation.map((item) => (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  'text-sm font-medium transition-colors hover:text-sigil-600',
                  pathname === item.href
                    ? 'text-sigil-600 border-b-2 border-sigil-600 pb-4'
                    : 'text-gray-700'
                )}
              >
                {item.name}
              </Link>
            ))}
          </div>

          {/* Desktop Search & Actions */}
          <div className="hidden md:flex items-center space-x-4">
            {/* Quick Search */}
            <div className="relative">
              <button
                onClick={() => setSearchOpen(!searchOpen)}
                className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                aria-label="Search"
              >
                <MagnifyingGlassIcon className="h-5 w-5" />
              </button>
              
              {searchOpen && (
                <div className="absolute right-0 top-full mt-2 w-80">
                  <SearchInput
                    placeholder="Search tools, stacks..."
                    onSubmit={handleSearch}
                    autoComplete={true}
                    className="shadow-lg"
                  />
                </div>
              )}
            </div>

            {/* CTA Buttons */}
            <Button variant="outline" size="sm" href="/submit">
              Submit Tool
            </Button>
            <Button size="sm" href="/discover">
              Browse Tools
            </Button>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-gray-400 hover:text-gray-600"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? (
                <XMarkIcon className="h-6 w-6" />
              ) : (
                <Bars3Icon className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-gray-200">
            <div className="py-4 space-y-4">
              {/* Mobile Search */}
              <div className="px-4">
                <SearchInput
                  placeholder="Search tools, stacks..."
                  onSubmit={(query) => {
                    handleSearch(query);
                    setMobileMenuOpen(false);
                  }}
                />
              </div>

              {/* Mobile Navigation */}
              <div className="space-y-1">
                {navigation.map((item) => (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={cn(
                      'block px-4 py-2 text-sm font-medium transition-colors',
                      pathname === item.href
                        ? 'text-sigil-600 bg-sigil-50'
                        : 'text-gray-700 hover:text-sigil-600 hover:bg-gray-50'
                    )}
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    {item.name}
                  </Link>
                ))}
              </div>

              {/* Mobile CTA */}
              <div className="px-4 pt-4 border-t border-gray-200 space-y-2">
                <Button 
                  variant="outline" 
                  className="w-full" 
                  href="/submit"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Submit Tool
                </Button>
                <Button 
                  className="w-full" 
                  href="/discover"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Browse Tools
                </Button>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Global Search Overlay */}
      {searchOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-25 z-40 md:hidden"
          onClick={() => setSearchOpen(false)}
        />
      )}
    </header>
  );
}