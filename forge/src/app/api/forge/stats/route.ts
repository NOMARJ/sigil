import { NextResponse } from "next/server";
import { forgeBackendFetch, FALLBACK_STATS } from "@/lib/forge-api";

export async function GET() {
  try {
    const data = await forgeBackendFetch({ path: "/stats" });
    return NextResponse.json(data);
  } catch (error) {
    console.error("[forge/stats] Backend error:", (error as Error).message);
    return NextResponse.json(FALLBACK_STATS);
  }
}
