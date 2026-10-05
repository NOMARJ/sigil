import { act, renderHook } from '@testing-library/react';
import useRescan from '@/hooks/useRescan';
import { rescanScan } from '@/lib/api';
import type { RescanResult } from '@/lib/types';

jest.mock('@/lib/api', () => ({ rescanScan: jest.fn() }));
const rescan = jest.mocked(rescanScan);

// [MOCK] Deterministic backend results; these tests perform no scan/network request.
describe('useRescan', () => {
  beforeEach(() => rescan.mockReset());
  it('reports pending state, returns the backend result and clears loading', async () => {
    let finish!: (value: RescanResult) => void;
    rescan.mockReturnValue(new Promise(resolve => { finish = resolve; }));
    const { result } = renderHook(() => useRescan());
    expect(result.current).toMatchObject({ isRescanning: false, rescanError: null });
    let pending!: Promise<RescanResult | null>;
    act(() => { pending = result.current.rescanScan('mock-scan'); });
    expect(result.current.isRescanning).toBe(true);
    expect(rescan).toHaveBeenCalledWith('mock-scan');
    const backendResult = { scan_id: 'mock-scan' } as unknown as RescanResult;
    await act(async () => { finish(backendResult); expect(await pending).toBe(backendResult); });
    expect(result.current).toMatchObject({ isRescanning: false, rescanError: null });
  });
  it.each([new Error('Backend unavailable'), 'non-Error failure'])('captures %s without leaving loading stuck', async (failure) => {
    rescan.mockRejectedValueOnce(failure);
    const { result } = renderHook(() => useRescan());
    await act(async () => { expect(await result.current.rescanScan('mock-scan')).toBeNull(); });
    expect(result.current.isRescanning).toBe(false);
    expect(result.current.rescanError).toBe(failure instanceof Error ? failure.message : 'Failed to rescan');
  });
  it('clears a previous error before a successful retry', async () => {
    rescan.mockRejectedValueOnce(new Error('First attempt failed'));
    const { result } = renderHook(() => useRescan());
    await act(async () => { await result.current.rescanScan('mock-scan'); });
    expect(result.current.rescanError).toBe('First attempt failed');
    const backendResult = { scan_id: 'mock-scan' } as unknown as RescanResult;
    rescan.mockResolvedValueOnce(backendResult);
    await act(async () => { expect(await result.current.rescanScan('mock-scan')).toBe(backendResult); });
    expect(result.current).toMatchObject({ isRescanning: false, rescanError: null });
  });
});
