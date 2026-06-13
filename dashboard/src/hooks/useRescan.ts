import { useState, useCallback } from 'react';
import * as api from '@/lib/api';
import type { RescanResult } from '@/lib/types';

interface UseRescanResult {
  isRescanning: boolean;
  rescanError: string | null;
  rescanScan: (scanId: string) => Promise<RescanResult | null>;
}

export default function useRescan(): UseRescanResult {
  const [isRescanning, setIsRescanning] = useState(false);
  const [rescanError, setRescanError] = useState<string | null>(null);

  const rescanScan = useCallback(async (scanId: string): Promise<RescanResult | null> => {
    setIsRescanning(true);
    setRescanError(null);

    try {
      return await api.rescanScan(scanId);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to rescan';
      setRescanError(message);
      return null;
    } finally {
      setIsRescanning(false);
    }
  }, []);

  return {
    isRescanning,
    rescanError,
    rescanScan,
  };
}
