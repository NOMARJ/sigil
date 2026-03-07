import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@auth0/nextjs-auth0";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const session = await getSession(request, NextResponse.next());
    
    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { step_id, user_id, data } = body;

    // In a real implementation, this would save to the database
    // For now, we'll just return a success response
    console.log(`Onboarding step completed: ${step_id} for user ${user_id}`, data);

    return NextResponse.json({
      success: true,
      step_id,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error("Error tracking onboarding step:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}