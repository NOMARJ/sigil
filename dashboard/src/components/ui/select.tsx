import React from 'react';

export function Select({ 
  children,
  value,
  onValueChange,
  className = ''
}: { 
  children: React.ReactNode;
  value?: string;
  onValueChange?: (value: string) => void;
  className?: string;
}) {
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export function SelectTrigger({ 
  children,
  className = ''
}: { 
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <button className={`flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}>
      {children}
    </button>
  );
}

export function SelectContent({ 
  children,
  className = ''
}: { 
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`relative z-50 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md ${className}`}>
      {children}
    </div>
  );
}

export function SelectItem({ 
  children,
  value,
  className = ''
}: { 
  children: React.ReactNode;
  value: string;
  className?: string;
}) {
  return (
    <div className={`relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50 ${className}`} data-value={value}>
      {children}
    </div>
  );
}

export function SelectValue({ 
  placeholder = '',
  className = ''
}: { 
  placeholder?: string;
  className?: string;
}) {
  return (
    <span className={className}>
      {placeholder}
    </span>
  );
}