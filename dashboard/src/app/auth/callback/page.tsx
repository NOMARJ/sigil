'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { supabase } from '@/lib/supabase'

export default function AuthCallbackPage() {
  const router = useRouter()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // If Supabase is not configured, redirect to login with an error
    if (!supabase) {
      setError('OAuth is not available. Supabase is not configured. Please use email/password login instead.')
      const timer = setTimeout(() => {
        router.push('/login')
      }, 3000)
      return () => clearTimeout(timer)
    }

    // Capture non-null reference for use in async callbacks
    const sb = supabase;

    let subscription: { unsubscribe: () => void } | undefined
    let timeoutId: ReturnType<typeof setTimeout> | undefined
    let redirectTimeoutId: ReturnType<typeof setTimeout> | undefined
    let cancelled = false

    // Wait for Supabase to process the OAuth callback
    // The hash fragment contains the tokens which Supabase auto-processes
    sb.auth.getSession().then(({ data: { session }, error: sessionError }) => {
      if (cancelled) return

      if (sessionError) {
        setError(sessionError.message)
        redirectTimeoutId = setTimeout(() => router.push('/login'), 3000)
        return
      }

      if (session) {
        // Session established successfully, redirect to dashboard
        router.push('/')
      } else {
        // No session yet — listen for the auth state change
        const { data: { subscription: sub } } = sb.auth.onAuthStateChange(
          (event, session) => {
            if (event === 'SIGNED_IN' && session) {
              sub.unsubscribe()
              router.push('/')
            }
          },
        )
        subscription = sub

        // Timeout fallback: if no auth event fires within 10 seconds, redirect to login
        timeoutId = setTimeout(() => {
          if (cancelled) return
          sub.unsubscribe()
          setError('Authentication timed out. Please try again.')
          redirectTimeoutId = setTimeout(() => router.push('/login'), 2000)
        }, 10000)
      }
    })

    return () => {
      cancelled = true
      subscription?.unsubscribe()
      if (timeoutId) clearTimeout(timeoutId)
      if (redirectTimeoutId) clearTimeout(redirectTimeoutId)
    }
  }, [router])

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950">
      <div className="text-center">
        {error ? (
          <>
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-red-500/10 border border-red-500/20 mb-4">
              <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-gray-100 mb-2">Authentication Error</h1>
            <p className="text-gray-400 mb-4">{error}</p>
            <p className="text-sm text-gray-500">Redirecting to login...</p>
          </>
        ) : (
          <>
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-brand-500 mb-4" />
            <h1 className="text-xl font-bold text-gray-100 mb-2">Signing you in...</h1>
            <p className="text-gray-400">Please wait a moment.</p>
          </>
        )}
      </div>
    </div>
  )
}
