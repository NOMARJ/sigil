import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function POST(): Promise<NextResponse> {
  try {
    const session = await auth0.getSession();

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    return NextResponse.json(
      {
        error:
          "Dashboard API key issuance is not available. Use Auth0 login for CLI access.",
      },
      { status: 501 },
    );
  } catch (error) {
    console.error("Error generating API key:", error);
    return NextResponse.json(
      { error: "Failed to generate API key" },
      { status: 500 }
    );
  }
}
