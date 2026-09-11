import "server-only";
import { NextRequest, NextResponse } from "next/server";

import { applyBackendSetCookies, jsonResponseFromBackend } from "./auth-cookies";
import { getBackendConfig } from "./backend-config";
import { requireAuth } from "./requireAuth";

/** Wrap a payload in the G2P request envelope the Agent Portal API expects. */
function envelope(payload: unknown, origin: string) {
    return {
        request_header: {
            sender_app_mnemonic: getBackendConfig().applicationMnemonic,
            sender_app_url: origin,
            request_id: crypto.randomUUID(),
            request_timestamp: new Date().toISOString(),
        },
        request_body: { request_payload: payload },
    };
}

/**
 * Proxy one Agent Portal API call, exactly as the staff portal proxies its
 * backend: the browser never holds a token, and this route reads the httpOnly
 * cookies server-side to build the backend's Authorization/Cookie/CSRF headers.
 */
export async function proxyToAgentApi(req: NextRequest, endpoint: string) {
    const auth = requireAuth(req);
    if (auth instanceof NextResponse) return auth;

    const backendConfig = getBackendConfig();
    let payload: unknown = {};
    try {
        payload = await req.json();
    } catch {
        payload = {};
    }

    const res = await fetch(`${backendConfig.backendApiUrl}/agent_portal/vc/${endpoint}`, {
        method: "POST",
        headers: auth.backendHeaders,
        body: JSON.stringify(envelope(payload, req.nextUrl.origin)),
        cache: "no-store",
    });

    return jsonResponseFromBackend(res);
}

/**
 * Issuance is the exception: on success the API replies with the PDF itself
 * rather than the JSON envelope, so the bytes are streamed through untouched
 * and the issuance headers are preserved for the client.
 */
export async function proxyIssue(req: NextRequest) {
    const auth = requireAuth(req);
    if (auth instanceof NextResponse) return auth;

    const backendConfig = getBackendConfig();
    let payload: unknown = {};
    try {
        payload = await req.json();
    } catch {
        payload = {};
    }

    const res = await fetch(`${backendConfig.backendApiUrl}/agent_portal/vc/issue`, {
        method: "POST",
        headers: auth.backendHeaders,
        body: JSON.stringify(envelope(payload, req.nextUrl.origin)),
        cache: "no-store",
    });

    if (!res.ok || !(res.headers.get("content-type") || "").includes("application/pdf")) {
        return jsonResponseFromBackend(res);
    }

    const target = new NextResponse(await res.arrayBuffer(), {
        status: res.status,
        headers: {
            "Content-Type": "application/pdf",
            "Content-Disposition": res.headers.get("Content-Disposition") ?? "attachment; filename=\"credential.pdf\"",
            "X-Issuance-Id": res.headers.get("X-Issuance-Id") ?? "",
            "X-Credential-Id": res.headers.get("X-Credential-Id") ?? "",
            "X-Vc-Type": res.headers.get("X-Vc-Type") ?? "",
        },
    });
    applyBackendSetCookies(res, target);
    return target;
}

async function proxyBinary(req: NextRequest, endpoint: string, defaultFilename: string) {
  const auth = requireAuth(req);
  if (auth instanceof NextResponse) return auth;

  const backendConfig = getBackendConfig();

  let payload: unknown = {};
  try {
    payload = await req.json();
  } catch {
    payload = {};
  }

  const res = await fetch(`${backendConfig.backendApiUrl}/agent_portal/vc/${endpoint}`, {
    method: "POST",
    headers: auth.backendHeaders,
    body: JSON.stringify(envelope(payload, req.nextUrl.origin)),
    cache: "no-store",
  });

  if (!res.ok || !(res.headers.get("content-type") || "").includes("application/pdf")) {
    return jsonResponseFromBackend(res);
  }

  const target = new NextResponse(await res.arrayBuffer(), {
    status: res.status,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": res.headers.get("Content-Disposition") ?? `attachment; filename="${defaultFilename}"`,
      "X-Issuance-Id": res.headers.get("X-Issuance-Id") ?? "",
      "X-Credential-Id": res.headers.get("X-Credential-Id") ?? "",
      "X-Vc-Type": res.headers.get("X-Vc-Type") ?? "",
    },
  });
  applyBackendSetCookies(res, target);
  return target;
}

export async function proxyCredIssuerIssue(req: NextRequest) {
  return proxyBinary(req, "issue/credissuer", "credential.pdf");
}
