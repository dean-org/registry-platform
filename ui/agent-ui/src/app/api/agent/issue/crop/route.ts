import { NextRequest } from "next/server";

import { proxyCropIssue } from "@/app/api/_lib/agent-proxy";

export async function POST(req: NextRequest) {
  return proxyCropIssue(req);
}
