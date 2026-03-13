import { getSession } from '@auth0/nextjs-auth0';
import { NextResponse } from 'next/server';

export async function GET() {
  try {
    const session = await getSession();
    
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // Return user profile from Auth0 session
    return NextResponse.json({
      id: session.user.sub,
      email: session.user.email,
      name: session.user.name || session.user.email,
      picture: session.user.picture,
      plan: 'pro', // Default plan for Auth0 users
      created_at: new Date().toISOString(),
    });
  } catch (error) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
}
