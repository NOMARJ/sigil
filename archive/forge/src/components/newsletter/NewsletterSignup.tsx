'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { forgeApi } from '@/lib/api';

interface NewsletterSignupProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'minimal' | 'footer';
}

export function NewsletterSignup({ 
  className = '', 
  size = 'md',
  variant = 'default' 
}: NewsletterSignupProps) {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email || isLoading) return;
    
    setIsLoading(true);
    setStatus('idle');
    
    try {
      const response = await forgeApi.subscribeToNewsletter({
        email,
        preferences: {
          security_alerts: true,
          tool_discoveries: true,
          weekly_digest: true,
          product_updates: true
        },
        source: 'forge'
      });
      
      if (response.success) {
        setStatus('success');
        setMessage(response.message);
        setEmail('');
      } else {
        setStatus('error');
        setMessage('Subscription failed. Please try again.');
      }
    } catch (error: any) {
      setStatus('error');
      setMessage(error.message || 'Something went wrong. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  if (status === 'success') {
    return (
      <div className={`
        ${variant === 'minimal' ? 'text-center' : 'bg-green-50 border border-green-200 rounded-lg p-4'} 
        ${className}
      `}>
        <div className="flex items-center space-x-2">
          <div className="flex-shrink-0">
            <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-medium text-green-800">
              Successfully subscribed!
            </h3>
            <p className="text-sm text-green-700 mt-1">
              {message || "You'll receive your first Forge Weekly this Sunday."}
            </p>
          </div>
        </div>
      </div>
    );
  }

  const sizeClasses = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg'
  };

  const variantClasses = {
    default: 'bg-white border border-gray-200 rounded-lg p-6',
    minimal: 'bg-transparent',
    footer: 'bg-gray-50 rounded-lg p-6'
  };

  return (
    <div className={`${variantClasses[variant]} ${className}`}>
      {variant !== 'minimal' && (
        <div className="mb-4">
          <h3 className={`font-semibold text-gray-900 ${
            size === 'lg' ? 'text-xl' : size === 'md' ? 'text-lg' : 'text-base'
          }`}>
            📬 Forge Weekly
          </h3>
          <p className={`text-gray-600 mt-1 ${sizeClasses[size]}`}>
            Get weekly AI security intelligence delivered to your inbox
          </p>
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1">
          <Input
            type="email"
            placeholder="Enter your email address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            disabled={isLoading}
            className={status === 'error' ? 'border-red-300 focus:border-red-500' : ''}
          />
        </div>
        <Button
          type="submit"
          loading={isLoading}
          disabled={isLoading || !email}
          className="whitespace-nowrap"
        >
          {isLoading ? 'Subscribing...' : 'Subscribe'}
        </Button>
      </form>
      
      {status === 'error' && (
        <div className="mt-3 text-sm text-red-600">
          ⚠️ {message}
        </div>
      )}
      
      {variant !== 'minimal' && (
        <div className="mt-3 text-xs text-gray-500">
          Weekly digest featuring new tools, security alerts, and threat intelligence. 
          <br />
          Unsubscribe anytime. No spam, ever.
        </div>
      )}
    </div>
  );
}