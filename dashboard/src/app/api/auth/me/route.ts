import { auth0 } from "@/lib/auth0";
import { NextResponse } from "next/server";

type ApiUser = {
  id?: string;
  email?: string;
  name?: string;
  role?: string;
  team_id?: string | null;
  created_at?: string;
};

type ApiSubscription = {
  plan?: string;
};

const USER_ROLES = new Set(["owner", "admin", "reviewer", "member", "viewer"]);
const PLAN_TIERS = new Set(["free", "pro", "team", "enterprise"]);

function apiBaseUrl(): string {
  const url = process.env.NEXT_PUBLIC_API_URL;
  if (!url) {
    throw new Error("NEXT_PUBLIC_API_URL is not configured");
  }
  return url;
}

function normalizeRole(role: unknown): string {
  return typeof role === "string" && USER_ROLES.has(role) ? role : "member";
}

function normalizePlan(plan: unknown): string {
  return typeof plan === "string" && PLAN_TIERS.has(plan) ? plan : "free";
}

async function fetchJson<T>(path: string, token: string): Promise<T> {
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

function emailUnverifiedResponse(email: unknown): NextResponse {
  return NextResponse.json(
    {
      error: "email_unverified",
      email: typeof email === "string" ? email : null,
    },
    { status: 403 },
  );
}

export async function GET(): Promise<NextResponse> {
  try {
    const session = await auth0.getSession();

    if (!session || !session.user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { token } = await auth0.getAccessToken();
    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    let apiUser: ApiUser;
    let subscription: ApiSubscription;
    try {
      [apiUser, subscription] = await Promise.all([
        fetchJson<ApiUser>("/auth/me", token),
        fetchJson<ApiSubscription>("/billing/subscription", token).catch(
          (): ApiSubscription => ({}),
        ),
      ]);
    } catch (error) {
      // The backend rejects tokens for unverified email addresses. When the
      // Auth0 session itself says the email is unverified, surface that as a
      // distinct state so the client can prompt the user to verify instead of
      // bouncing them back to the login page.
      if (session.user.email_verified === false) {
        return emailUnverifiedResponse(session.user.email);
      }
      throw error;
    }

    return NextResponse.json({
      id: apiUser.id ?? session.user.sub,
      email: apiUser.email ?? session.user.email,
      name: apiUser.name || session.user.name || session.user.email,
      avatar_url: session.user.picture ?? null,
      role: normalizeRole(apiUser.role),
      plan: normalizePlan(subscription.plan),
      team_id: apiUser.team_id ?? null,
      created_at: apiUser.created_at ?? new Date().toISOString(),
    });
  } catch {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }
}
