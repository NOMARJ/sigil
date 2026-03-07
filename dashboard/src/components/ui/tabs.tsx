import React from 'react';

export function Tabs({ 
  children,
  defaultValue,
  value,
  onValueChange,
  className = ''
}: { 
  children: React.ReactNode;
  defaultValue?: string;
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

export function TabsList({ 
  children,
  className = ''
}: { 
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`inline-flex h-10 items-center justify-center rounded-md bg-muted p-1 text-muted-foreground ${className}`}>
      {children}
    </div>
  );
}

export function TabsTrigger({ 
  children,
  value,
  className = ''
}: { 
  children: React.ReactNode;
  value: string;
  className?: string;
}) {
  return (
    <button className={`inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 py-1.5 text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm ${className}`} data-value={value}>
      {children}
    </button>
  );
}

export function TabsContent({ 
  children,
  value,
  className = ''
}: { 
  children: React.ReactNode;
  value: string;
  className?: string;
}) {
  return (
    <div className={`mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 ${className}`} data-value={value}>
      {children}
    </div>
  );
}