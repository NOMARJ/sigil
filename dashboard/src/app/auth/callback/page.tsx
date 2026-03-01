'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function AuthCallbackPage() {
  const router = useRouter()

  useEffect(() => {
    // Auth0 handles the OAuth callback via /api/auth/callback
    // This page is only shown briefly during redirect
    router.replace('/')
  }, [router])

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950">
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-brand-500 mb-4" />
        <h1 className="text-xl font-bold text-gray-100 mb-2">Completing login...</h1>
        <p className="text-gray-400">Please wait a moment.</p>
      </div>
    </div>
  )
}
