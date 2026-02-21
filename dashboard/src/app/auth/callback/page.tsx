'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function AuthCallbackPage() {
  const router = useRouter()

  useEffect(() => {
    // Supabase automatically handles the OAuth callback
    // The session will be set in the auth context
    // Just redirect to dashboard after a brief moment
    const timer = setTimeout(() => {
      router.push('/dashboard')
    }, 1000)

    return () => clearTimeout(timer)
  }, [router])

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-50">
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mb-4"></div>
        <h1 className="text-2xl font-bold text-gray-900 mb-2">Signing you in...</h1>
        <p className="text-gray-600">Please wait a moment.</p>
      </div>
    </div>
  )
}
