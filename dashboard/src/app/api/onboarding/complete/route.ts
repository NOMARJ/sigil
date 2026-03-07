import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@auth0/nextjs-auth0";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const session = await getSession(request, NextResponse.next());
    
    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { user_id, completion_data } = body;

    // In a real implementation, this would:
    // 1. Mark onboarding as complete in the user record
    // 2. Send welcome email
    // 3. Set up any necessary permissions
    // 4. Trigger analytics events
    
    console.log(`Onboarding completed for user ${user_id}`, completion_data);

    return NextResponse.json({
      success: true,
      completed_at: new Date().toISOString(),
      message: "Onboarding completed successfully"
    });
  } catch (error) {
    console.error("Error completing onboarding:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}