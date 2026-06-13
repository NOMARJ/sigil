import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function POST(): Promise<NextResponse> {
  try {
    const session = await auth0.getSession();

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    return NextResponse.json(
      { error: "Onboarding step persistence is not configured." },
      { status: 501 },
    );
  } catch {
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 },
    );
  }
}
