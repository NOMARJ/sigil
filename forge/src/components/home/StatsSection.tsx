'use client';

import { useEffect, useState } from 'react';

const stats = [
  { label: 'Tools Indexed', value: 2847, prefix: '', suffix: '+' },
  { label: 'Trust Scores', value: 15420, prefix: '', suffix: '+' },
  { label: 'Vulnerabilities Found', value: 456, prefix: '', suffix: '' },
  { label: 'Downloads Tracked', value: 1200000, prefix: '', suffix: 'M+' },
];

function AnimatedCounter({ 
  target, 
  prefix = '', 
  suffix = '', 
  duration = 2000 
}: { 
  target: number; 
  prefix?: string; 
  suffix?: string; 
  duration?: number; 
}) {
  const [count, setCount] = useState(0);
  
  useEffect(() => {
    let start = 0;
    const increment = target / (duration / 16);
    
    const timer = setInterval(() => {
      start += increment;
      if (start >= target) {
        setCount(target);
        clearInterval(timer);
      } else {
        setCount(Math.floor(start));
      }
    }, 16);
    
    return () => clearInterval(timer);
  }, [target, duration]);
  
  const formatNumber = (num: number) => {
    if (suffix === 'M+') {
      return (num / 1000000).toFixed(1);
    }
    return num.toLocaleString();
  };
  
  return (
    <span>
      {prefix}{formatNumber(count)}{suffix}
    </span>
  );
}

export function StatsSection() {
  const [inView, setInView] = useState(false);
  
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
        }
      },
      { threshold: 0.1 }
    );
    
    const element = document.getElementById('stats-section');
    if (element) {
      observer.observe(element);
    }
    
    return () => observer.disconnect();
  }, []);
  
  return (
    <section id="stats-section" className="py-16 bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
          {stats.map((stat, index) => (
            <div key={stat.label} className="text-center">
              <div className="text-3xl lg:text-4xl font-bold text-gray-900 mb-2">
                {inView ? (
                  <AnimatedCounter 
                    target={stat.value} 
                    prefix={stat.prefix}
                    suffix={stat.suffix}
                    duration={2000 + index * 200}
                  />
                ) : (
                  '0'
                )}
              </div>
              <div className="text-sm font-medium text-gray-600">
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}