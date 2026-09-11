import { NextRequest } from "next/server";

import { proxyCredIssuerIssue } from "@/app/api/_lib/agent-proxy";

export async function POST(req: NextRequest) {
  return proxyCredIssuerIssue(req);
}