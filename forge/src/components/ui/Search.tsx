'use client';

import { useState, useRef, useEffect } from 'react';
import { clsx } from 'clsx';
import { MagnifyingGlassIcon, XMarkIcon, ChevronDownIcon } from '@heroicons/react/24/outline';
import { useDebounce } from 'use-debounce';

interface SearchInputProps {
  placeholder?: string;
  value?: string;
  onChange?: (value: string) => void;
  onSubmit?: (value: string) => void;
  autoComplete?: boolean;
  suggestions?: string[];
  loading?: boolean;
  className?: string;
}

export function SearchInput({ 
  placeholder = "Search tools, stacks, or skills...",
  value = "",
  onChange,
  onSubmit,
  autoComplete = false,
  suggestions = [],
  loading = false,
  className
}: SearchInputProps) {
  const [inputValue, setInputValue] = useState(value);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [debouncedValue] = useDebounce(inputValue, 300);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (onChange && debouncedValue !== value) {
      onChange(debouncedValue);
    }
  }, [debouncedValue, onChange, value]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (onSubmit) {
      onSubmit(inputValue);
    }
    setShowSuggestions(false);
  };

  const handleSuggestionClick = (suggestion: string) => {
    setInputValue(suggestion);
    if (onSubmit) {
      onSubmit(suggestion);
    }
    setShowSuggestions(false);
  };

  const clearSearch = () => {
    setInputValue('');
    if (onChange) {
      onChange('');
    }
    inputRef.current?.focus();
  };

  return (
    <div className={clsx('relative', className)}>
      <form onSubmit={handleSubmit}>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <MagnifyingGlassIcon 
              className={clsx(
                'h-5 w-5',
                loading ? 'text-sigil-500 animate-pulse' : 'text-gray-400'
              )} 
            />
          </div>
          
          <input
            ref={inputRef}
            type="text"
            className={clsx(
              'block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-lg',
              'placeholder-gray-500 text-gray-900',
              'focus:outline-none focus:ring-2 focus:ring-sigil-500 focus:border-sigil-500',
              'transition-all duration-200'
            )}
            placeholder={placeholder}
            value={inputValue}
            onChange={(e) => {
              setInputValue(e.target.value);
              if (autoComplete && suggestions.length > 0) {
                setShowSuggestions(true);
              }
            }}
            onFocus={() => {
              if (autoComplete && suggestions.length > 0) {
                setShowSuggestions(true);
              }
            }}
            onBlur={() => {
              // Delay hiding suggestions to allow clicking
              setTimeout(() => setShowSuggestions(false), 200);
            }}
          />
          
          {inputValue && (
            <button
              type="button"
              className="absolute inset-y-0 right-0 pr-3 flex items-center"
              onClick={clearSearch}
            >
              <XMarkIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
            </button>
          )}
        </div>
      </form>
      
      {/* Autocomplete Suggestions */}
      {showSuggestions && autoComplete && suggestions.length > 0 && (
        <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg">
          <ul className="py-1 max-h-60 overflow-auto">
            {suggestions.map((suggestion, index) => (
              <li
                key={index}
                className="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm"
                onClick={() => handleSuggestionClick(suggestion)}
              >
                {suggestion}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

interface FilterOption {
  label: string;
  value: string;
  count?: number;
}

interface FilterDropdownProps {
  label: string;
  options: FilterOption[];
  selectedValues: string[];
  onChange: (values: string[]) => void;
  multiple?: boolean;
  className?: string;
}

export function FilterDropdown({ 
  label, 
  options, 
  selectedValues, 
  onChange, 
  multiple = true,
  className 
}: FilterDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleOptionClick = (value: string) => {
    if (multiple) {
      const newValues = selectedValues.includes(value)
        ? selectedValues.filter(v => v !== value)
        : [...selectedValues, value];
      onChange(newValues);
    } else {
      onChange([value]);
      setIsOpen(false);
    }
  };

  const selectedCount = selectedValues.length;
  const displayText = selectedCount === 0 
    ? label 
    : multiple 
      ? `${label} (${selectedCount})`
      : options.find(opt => opt.value === selectedValues[0])?.label || label;

  return (
    <div ref={dropdownRef} className={clsx('relative', className)}>
      <button
        type="button"
        className={clsx(
          'inline-flex items-center px-3 py-2 border border-gray-300 rounded-lg',
          'bg-white text-sm font-medium text-gray-700',
          'hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-sigil-500',
          'transition-all duration-200',
          isOpen && 'ring-2 ring-sigil-500',
          selectedCount > 0 && 'bg-sigil-50 border-sigil-300 text-sigil-700'
        )}
        onClick={() => setIsOpen(!isOpen)}
      >
        {displayText}
        <ChevronDownIcon 
          className={clsx(
            'ml-2 h-4 w-4 transition-transform duration-200',
            isOpen && 'rotate-180'
          )} 
        />
      </button>

      {isOpen && (
        <div className="absolute z-10 mt-1 w-56 bg-white border border-gray-300 rounded-lg shadow-lg">
          <ul className="py-1 max-h-60 overflow-auto">
            {options.map((option) => {
              const isSelected = selectedValues.includes(option.value);
              return (
                <li
                  key={option.value}
                  className={clsx(
                    'px-3 py-2 cursor-pointer text-sm flex items-center justify-between',
                    'hover:bg-gray-100',
                    isSelected && 'bg-sigil-50 text-sigil-700'
                  )}
                  onClick={() => handleOptionClick(option.value)}
                >
                  <span>{option.label}</span>
                  {option.count !== undefined && (
                    <span className="text-gray-400">({option.count})</span>
                  )}
                  {isSelected && multiple && (
                    <span className="ml-2 text-sigil-600">✓</span>
                  )}
                </li>
              );
            })}
          </ul>
          
          {multiple && selectedValues.length > 0 && (
            <div className="border-t border-gray-200 px-3 py-2">
              <button
                type="button"
                className="text-sm text-gray-500 hover:text-gray-700"
                onClick={() => onChange([])}
              >
                Clear all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}