import React from 'react';
import {render,screen} from '@testing-library/react';
import posthog from 'posthog-js';
import Provider from '@/components/PostHogProvider';
// [MOCK] SDK initialization is inert; key cannot authorize any telemetry service.
jest.mock('posthog-js',()=>({__esModule:true,default:{init:jest.fn()}}));
const saved={...process.env};
afterEach(()=>{process.env={...saved};jest.clearAllMocks();Object.defineProperty(navigator,'doNotTrack',{value:undefined,configurable:true});});
it('renders children without configured telemetry',()=>{delete process.env.NEXT_PUBLIC_POSTHOG_KEY;render(<Provider>child sentinel</Provider>);expect(screen.getByText('child sentinel')).toBeInTheDocument();expect(posthog.init).not.toHaveBeenCalled();});
it('honors do not track',()=>{process.env.NEXT_PUBLIC_POSTHOG_KEY='MOCK-UNUSABLE-KEY';Object.defineProperty(navigator,'doNotTrack',{value:'1',configurable:true});render(<Provider>child</Provider>);expect(posthog.init).not.toHaveBeenCalled();});
it.each([undefined,'https://telemetry.invalid'])('configures explicit capture defaults with host %p',host=>{process.env.NEXT_PUBLIC_POSTHOG_KEY='MOCK-UNUSABLE-KEY';if(host)process.env.NEXT_PUBLIC_POSTHOG_HOST=host;else delete process.env.NEXT_PUBLIC_POSTHOG_HOST;render(<Provider>child</Provider>);expect(posthog.init).toHaveBeenCalledWith('MOCK-UNUSABLE-KEY',{api_host:host??'https://app.posthog.com',autocapture:false,capture_pageview:true,persistence:'localStorage+cookie'});});
