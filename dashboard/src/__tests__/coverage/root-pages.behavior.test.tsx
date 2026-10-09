import React from 'react';
import {render,screen,waitFor,act} from '@testing-library/react';
import * as api from '@/lib/api';
import Dashboard from '@/app/page';
import RootLayout,{metadata,viewport} from '@/app/layout';
// [MOCK] Data, fonts, telemetry and shell boundaries are inert and do not fetch assets.
jest.mock('@/lib/api',()=>({getDashboardStats:jest.fn(),listScans:jest.fn()}));
jest.mock('next/font/google',()=>({Inter:()=>({variable:'mock-inter'}),JetBrains_Mono:()=>({variable:'mock-mono'})}));
jest.mock('@/components/PostHogProvider',()=>({__esModule:true,default:({children}:{children:React.ReactNode})=><section data-testid="telemetry">{children}</section>}));
jest.mock('@/components/LayoutShell',()=>({__esModule:true,default:({children}:{children:React.ReactNode})=><section data-testid="shell">{children}</section>}));
jest.mock('@/components/ui/EnhancedStatsCard',()=>({EnhancedStatsCard:({title,value}:{title:string;value:number})=><div>{title}: {value}</div>}));
jest.mock('@/components/ScanTable',()=>({__esModule:true,default:({scans}:{scans:unknown[]})=><output>Mock scans: {scans.length}</output>}));
const stats=jest.mocked(api.getDashboardStats), scans=jest.mocked(api.listScans);
beforeEach(()=>{jest.resetAllMocks();stats.mockResolvedValue({total_scans:0,threats_blocked:2,packages_approved:3,critical_findings:4,scans_trend:-2,threats_trend:3} as never);scans.mockResolvedValue({items:[]} as never);});
it('composes root document and metadata',()=>{const tree=RootLayout({children:'sentinel'});expect(tree.type).toBe('html');expect(tree.props.lang).toBe('en');expect(tree.props.className).toContain('mock-inter mock-mono');expect(metadata.title).toContain('Sigil');expect(viewport.width).toBe('device-width');const body=tree.props.children;render(body.props.children);expect(screen.getByTestId('telemetry')).toContainElement(screen.getByTestId('shell'));expect(screen.getByText('sentinel')).toBeInTheDocument();});
it('loads overview and bounded recent scans',async()=>{render(<Dashboard/>);await screen.findByText('TOTAL SCANS: 0');expect(screen.getByText(/haven.t run any scans yet/)).toBeInTheDocument();expect(screen.getByText('Mock scans: 0')).toBeInTheDocument();expect(scans).toHaveBeenCalledWith({page:1,per_page:5});expect(screen.getByRole('link',{name:'View all'})).toHaveAttribute('href','/scans');});
it.each([new Error('MOCK failure'),'MOCK non-error'])('shows fetch failure %p',async error=>{stats.mockRejectedValue(error);render(<Dashboard/>);await screen.findByText(error instanceof Error?error.message:'Failed to load dashboard data.');});
it('ignores completion after unmount',async()=>{let resolve!:(value:unknown)=>void;stats.mockReturnValue(new Promise(done=>{resolve=done;}) as never);const view=render(<Dashboard/>);view.unmount();await act(async()=>resolve({total_scans:1}));expect(view.container).toBeEmptyDOMElement();});
it('renders nonzero scans without first scan message',async()=>{stats.mockResolvedValue({total_scans:1,threats_blocked:0,packages_approved:0,critical_findings:0} as never);scans.mockResolvedValue({items:[{id:'MOCK'}]} as never);render(<Dashboard/>);await waitFor(()=>expect(screen.getByText('Mock scans: 1')).toBeInTheDocument());expect(screen.queryByText(/haven.t run any scans yet/)).not.toBeInTheDocument();});
