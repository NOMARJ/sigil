import React from 'react';
import {render,screen,fireEvent} from '@testing-library/react';
import {usePathname} from 'next/navigation';
import LayoutShell from '@/components/LayoutShell';
// [MOCK] Provider and visual boundaries expose composition without identity/network access.
jest.mock('@auth0/nextjs-auth0/client',()=>({Auth0Provider:({children}:{children:React.ReactNode})=><section data-testid="sdk">{children}</section>}));
jest.mock('@/lib/auth',()=>({AuthProvider:({children}:{children:React.ReactNode})=><section data-testid="session">{children}</section>}));
jest.mock('@/components/AuthGuard',()=>({__esModule:true,default:({children}:{children:React.ReactNode})=><section data-testid="guard">{children}</section>}));
jest.mock('@/components/Sidebar',()=>({__esModule:true,default:({isOpen,onClose}:{isOpen:boolean;onClose:()=>void})=><button onClick={onClose}>Sidebar {isOpen?'open':'closed'}</button>}));
jest.mock('@/components/V2NotificationBanner',()=>({__esModule:true,default:()=> <aside>Mock banner</aside>}));
it.each(['/login','/login/nested'])('uses full screen login layout %s',path=>{jest.mocked(usePathname).mockReturnValue(path);render(<LayoutShell>child sentinel</LayoutShell>);expect(screen.getByText('child sentinel')).toBeInTheDocument();expect(screen.getByTestId('sdk')).toContainElement(screen.getByTestId('session'));expect(screen.getByTestId('session')).toContainElement(screen.getByTestId('guard'));expect(screen.queryByLabelText('Open sidebar')).not.toBeInTheDocument();});
it('opens and closes mobile sidebar on dashboard',()=>{jest.mocked(usePathname).mockReturnValue('/');render(<LayoutShell>child sentinel</LayoutShell>);expect(screen.getByText('Mock banner')).toBeInTheDocument();fireEvent.click(screen.getByLabelText('Open sidebar'));expect(screen.getByText('Sidebar open')).toBeInTheDocument();fireEvent.click(screen.getByText('Sidebar open'));expect(screen.getByText('Sidebar closed')).toBeInTheDocument();});
