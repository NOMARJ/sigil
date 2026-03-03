'use client';

import { forwardRef } from 'react';
import { clsx } from 'clsx';
import Link from 'next/link';
import { ButtonProps } from '@/types';

const Button = forwardRef<HTMLButtonElement | HTMLAnchorElement, ButtonProps>(
  ({ 
    className, 
    children, 
    variant = 'primary', 
    size = 'md', 
    disabled = false, 
    loading = false,
    onClick,
    href,
    type = 'button',
    ...props 
  }, ref) => {
    const baseClasses = [
      'inline-flex items-center justify-center',
      'font-medium rounded-lg transition-all duration-200',
      'focus:outline-none focus:ring-2 focus:ring-offset-2',
      'disabled:opacity-50 disabled:cursor-not-allowed',
      loading && 'cursor-wait'
    ];

    const variants = {
      primary: [
        'bg-sigil-600 text-white shadow-sm',
        'hover:bg-sigil-700 focus:ring-sigil-500',
        'border border-transparent'
      ],
      secondary: [
        'bg-gray-100 text-gray-900 shadow-sm',
        'hover:bg-gray-200 focus:ring-gray-500',
        'border border-gray-200'
      ],
      outline: [
        'bg-transparent text-sigil-600 shadow-sm',
        'hover:bg-sigil-50 focus:ring-sigil-500',
        'border border-sigil-300'
      ],
      ghost: [
        'bg-transparent text-gray-700',
        'hover:bg-gray-100 focus:ring-gray-500'
      ],
      danger: [
        'bg-error text-white shadow-sm',
        'hover:bg-red-700 focus:ring-red-500',
        'border border-transparent'
      ]
    };

    const sizes = {
      sm: 'px-3 py-1.5 text-sm h-8',
      md: 'px-4 py-2 text-sm h-10',
      lg: 'px-6 py-3 text-base h-12'
    };

    const classes = clsx(
      baseClasses,
      variants[variant],
      sizes[size],
      className
    );

    const content = (
      <>
        {loading && (
          <svg 
            className="animate-spin -ml-1 mr-2 h-4 w-4" 
            fill="none" 
            viewBox="0 0 24 24"
          >
            <circle 
              className="opacity-25" 
              cx="12" 
              cy="12" 
              r="10" 
              stroke="currentColor" 
              strokeWidth="4"
            />
            <path 
              className="opacity-75" 
              fill="currentColor" 
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
        {children}
      </>
    );

    if (href) {
      return (
        <Link 
          href={href}
          className={classes}
          ref={ref as React.Ref<HTMLAnchorElement>}
          {...props}
        >
          {content}
        </Link>
      );
    }

    return (
      <button
        type={type}
        className={classes}
        disabled={disabled || loading}
        onClick={onClick}
        ref={ref as React.Ref<HTMLButtonElement>}
        {...props}
      >
        {content}
      </button>
    );
  }
);

Button.displayName = 'Button';

export { Button };