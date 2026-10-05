import { act, renderHook } from '@testing-library/react';
import useBannerDismissal from '@/hooks/useBannerDismissal';

// [MOCK] Browser cookie storage in jsdom; no production user state.
describe('useBannerDismissal', () => {
  afterEach(() => {
    for (const cookie of document.cookie.split(';')) {
      document.cookie = `${cookie.split('=')[0].trim()}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
    }
  });
  it('shows an undismissed banner even when unrelated cookies exist', () => {
    document.cookie = 'unrelated=true;path=/';
    const { result } = renderHook(() => useBannerDismissal('mock-launch'));
    expect(result.current.isDismissed).toBe(false);
  });
  it.each(['true', 'false', ''])('restores dismissal only for the persisted true value %s', value => {
    document.cookie = `banner_dismissed_mock-launch=${value};path=/`;
    const { result } = renderHook(() => useBannerDismissal('mock-launch'));
    expect(result.current.isDismissed).toBe(value === 'true');
  });
  it('persists dismissal for the selected banner without changing other cookies', () => {
    document.cookie = 'unrelated=keep;path=/';
    const { result } = renderHook(() => useBannerDismissal('mock-launch'));
    act(() => result.current.dismissBanner());
    expect(result.current.isDismissed).toBe(true);
    expect(document.cookie).toContain('banner_dismissed_mock-launch=true');
    expect(document.cookie).toContain('unrelated=keep');
  });
  it('loads a different banner independently when the identifier changes', () => {
    document.cookie = 'banner_dismissed_mock-first=true;path=/';
    const { result, rerender } = renderHook(({ id }) => useBannerDismissal(id), { initialProps: { id: 'mock-first' } });
    expect(result.current.isDismissed).toBe(true);
    rerender({ id: 'mock-second' });
    expect(result.current.isDismissed).toBe(false);
    act(() => result.current.dismissBanner());
    expect(document.cookie).toContain('banner_dismissed_mock-second=true');
  });
});
