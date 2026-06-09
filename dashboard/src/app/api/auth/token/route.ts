import { auth0 } from "@/lib/auth0";
import { NextResponse } from "next/server";

export async function GET(): Promise<NextResponse> {
  try {
    const { token } = await auth0.getAccessToken();
    return NextResponse.json({ accessToken: token });
  } catch {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }
}
