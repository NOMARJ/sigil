import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

type AuthRouteContext = {
  params: { auth0: string } | Promise<{ auth0: string }>;
};

export async function GET(
  request: NextRequest,
  context: AuthRouteContext,
): Promise<NextResponse> {
  const { auth0: action } = await context.params;
  const url = new URL(request.url);

  if (action === "signup") {
    url.pathname = "/auth/login";
    url.searchParams.set("screen_hint", "signup");
    return NextResponse.redirect(url);
  }

  if (action === "login" || action === "logout" || action === "callback") {
    url.pathname = `/auth/${action}`;
    return NextResponse.redirect(url);
  }

  return NextResponse.json({ error: "Unknown auth route" }, { status: 404 });
}
