import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '@/lib/auth';
// [MOCK] fetch is inert and identities use reserved invalid addresses.
const http = jest.fn();
function Consumer() { const a = useAuth(); return <output>{JSON.stringify({ user:a.user, loading:a.loading, authenticated:a.isAuthenticated, unverified:a.emailUnverified, email:a.unverifiedEmail })}</output>; }
const state = () => JSON.parse(screen.getByRole('status').textContent!);
beforeEach(() => { http.mockReset(); global.fetch = http; });
it('requires a provider', () => { function Invalid(){useAuth();return null;} expect(() => render(<Invalid />)).toThrow('useAuth must be used within AuthProvider'); });
it('restores session identity and safe defaults', async () => {
 http.mockResolvedValue({ok:true,json:async()=>({id:'MOCK',email:'nobody@example.invalid'})});
 render(<AuthProvider><Consumer /></AuthProvider>);
 await waitFor(()=>expect(state().loading).toBe(false));
 expect(state().user).toEqual(expect.objectContaining({name:'nobody@example.invalid',avatar_url:null}));
 expect(state().authenticated).toBe(true);
 expect(http).toHaveBeenCalledWith('/api/auth/me',{credentials:'include',cache:'no-store'});
});
it.each(['rejection','missing-id','unauthorized','bad-json','other-forbidden'])('settles signed out for %s',async reason=>{
 if(reason==='rejection')http.mockRejectedValue(new Error('MOCK timeout'));
 else {
  const json = jest.fn(reason==='bad-json'?()=>Promise.reject(new Error('MOCK malformed JSON')):async()=>({}));
  http.mockResolvedValue({ok:reason==='missing-id'||reason==='bad-json',status:reason==='bad-json'?200:reason==='other-forbidden'?403:401,json});
 }
 render(<AuthProvider><Consumer /></AuthProvider>);
 await waitFor(()=>expect(state().loading).toBe(false));
 expect(state()).toEqual({user:null,loading:false,authenticated:false,unverified:false,email:null});
 if(reason==='bad-json')expect((await http.mock.results[0].value).json).toHaveBeenCalledTimes(1);
});
it.each(['nobody@example.invalid',9])('retains unverified state and sanitizes email %p',async email=>{
 http.mockResolvedValue({ok:false,status:403,json:async()=>({error:'email_unverified',email})});
 render(<AuthProvider><Consumer /></AuthProvider>);
 await waitFor(()=>expect(state().unverified).toBe(true));
 expect(state().email).toBe(typeof email==='string'?email:null);
});
it('ignores completion after unmount',async()=>{
 let resolve!:(value:unknown)=>void;
 http.mockReturnValue(new Promise(done=>{resolve=done;}));
 const view=render(<AuthProvider><Consumer /></AuthProvider>);
 expect(state().loading).toBe(true);view.unmount();
 await act(async()=>resolve({ok:true,json:async()=>({id:'MOCK-late'})}));
 expect(view.container).toBeEmptyDOMElement();
});
