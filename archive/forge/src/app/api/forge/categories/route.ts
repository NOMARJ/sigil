import { NextResponse } from "next/server";
import { forgeBackendFetch, FALLBACK_CATEGORIES } from "@/lib/forge-api";

export async function GET() {
  try {
    const data = await forgeBackendFetch({ path: "/categories" });
    return NextResponse.json(data);
  } catch (error) {
    console.error(
      "[forge/categories] Backend error:",
      (error as Error).message
    );
    return NextResponse.json(FALLBACK_CATEGORIES);
  }
}
