import React from 'react';
import {render,screen} from '@testing-library/react';
import {useAuth} from '@/lib/auth';
import Analytics from '@/app/forge/analytics/page';
import Monitoring from '@/app/forge/monitoring/page';
import Stacks from '@/app/forge/stacks/page';
import Settings from '@/app/forge/settings/page';
import Tools from '@/app/forge/tools/page';
// [MOCK] Sentinel auth state and gate boundary isolate each page's required plan contract.
jest.mock('@/lib/auth',()=>({useAuth:jest.fn()}));
jest.mock('@/components/PlanGate',()=>({__esModule:true,default:({children,requiredPlan,currentPlan}:{children:React.ReactNode;requiredPlan:string;currentPlan:string})=><section data-testid="gate" data-required={requiredPlan} data-current={currentPlan}>{children}</section>}));
it.each([[Analytics,'Analytics','pro'],[Monitoring,'Monitoring','team'],[Stacks,'Stacks','team'],[Settings,'Forge Settings','pro'],[Tools,'My Tools','pro']] as const)('page %p waits for auth and passes plan requirement', (Page,title,required)=>{
 jest.mocked(useAuth).mockReturnValue({user:null} as never);
 const view=render(<Page/>);expect(screen.getByText('Loading...')).toBeInTheDocument();
 jest.mocked(useAuth).mockReturnValue({user:{id:'MOCK',plan:'enterprise'}} as never);
 view.rerender(<Page/>);
 expect(screen.getByRole('heading',{name:title})).toBeInTheDocument();
 expect(screen.getByTestId('gate')).toHaveAttribute('data-required',required);
 expect(screen.getByTestId('gate')).toHaveAttribute('data-current','enterprise');
 expect(screen.getByText(title==='Forge Settings'?'Settings Not Available':title==='My Tools'?'Tool Tracking Unavailable':'Coming Soon')).toBeInTheDocument();
});
