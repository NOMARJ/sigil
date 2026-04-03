import { useState, useCallback } from 'react';

export interface RescanResult {
  scan_id: string;
  original_score: number;
  new_score: number;
  score_change: number;
  score_change_percentage: number;
  original_findings: number;
  new_findings: number;
  findings_change: number;
  rescanned_at: string;
  success: boolean;
}

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
      const response = await fetch(`/api/rescan/${scanId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(error || 'Failed to rescan');
      }

      const result: RescanResult = await response.json();
      return result;
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