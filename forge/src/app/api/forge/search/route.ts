import { NextRequest, NextResponse } from "next/server";
import { forgeBackendFetch, FALLBACK_SEARCH } from "@/lib/forge-api";

export async function GET(request: NextRequest) {
  try {
    const queryString = request.nextUrl.searchParams.toString();
    const data = await forgeBackendFetch({
      path: "/search",
      queryString,
    });
    return NextResponse.json(data);
  } catch (error) {
    console.error("[forge/search] Backend error:", (error as Error).message);
    return NextResponse.json(FALLBACK_SEARCH);
  }
}
