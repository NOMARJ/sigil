import { NextRequest, NextResponse } from "next/server";
import { forgeBackendFetch } from "@/lib/forge-api";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ ecosystem: string; name: string }> }
) {
  const { ecosystem, name } = await params;
  try {
    const data = await forgeBackendFetch({
      path: `/tool/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}/matches`,
    });
    return NextResponse.json(data);
  } catch (error) {
    console.error(
      `[forge/tools/${ecosystem}/${name}/matches] Backend error:`,
      (error as Error).message
    );
    return NextResponse.json([]);
  }
}
