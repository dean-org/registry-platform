'use client';

/**
 * The whole agent workflow, on one screen.
 *
 * It is deliberately a single page with four stages rather than a wizard across
 * routes: the agent is standing at a counter with a person in front of them, and
 * the beneficiary's authentication expires in minutes. Everything they need to
 * see — who was found, whether the authentication landed, how long is left —
 * stays visible at once.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import {
  ApiError,
  api,
  type AuthStatus,
  type Beneficiary,
  type VcType,
} from "@/api/client";

/** Stop polling eventually — the beneficiary may simply walk away. */
const POLL_TIMEOUT_MS = 5 * 60 * 1000;

type Stage = "lookup" | "authenticate" | "issue" | "done";

export default function IssueFlow() {
  const [nationalId, setNationalId] = useState("");
  const [vcTypes, setVcTypes] = useState<VcType[]>([]);
  const [vcType, setVcType] = useState<string>("");
  const [beneficiary, setBeneficiary] = useState<Beneficiary | null>(null);
  const [authId, setAuthId] = useState<string>("");
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [stage, setStage] = useState<Stage>("lookup");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>("");
  const [issued, setIssued] = useState<{
    filename: string;
    issuanceId: string;
  } | null>(null);

  const pollRef = useRef<number | null>(null);
  const popupRef = useRef<Window | null>(null);

  useEffect(() => {
    api.vcTypes()
      .then((r) => {
        setVcTypes(r.vc_types);

        if (r.vc_types.length) {
          setVcType(r.vc_types[0].config_id);
        }
      })
      .catch((e: ApiError) => setError(e.message));
  }, []);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  function reset() {
    stopPolling();

    popupRef.current?.close?.();
    popupRef.current = null;

    setBeneficiary(null);
    setAuthId("");
    setStatus(null);
    setIssued(null);
    setError("");
    setStage("lookup");
    setNationalId("");
  }

  async function onLookup(e: React.FormEvent) {
    e.preventDefault();

    setBusy(true);
    setError("");

    try {
      const found = await api.lookup(
        nationalId.trim(),
        vcType || undefined,
      );

      setBeneficiary(found);
      setStage(found.eligible ? "authenticate" : "lookup");

      if (!found.eligible) {
        setError(
          found.reason ??
            "This record cannot be issued a credential.",
        );
      }
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  }

  async function onAuthenticate() {
    if (!beneficiary) return;

    setBusy(true);
    setError("");

    try {
      const started = await api.startAuthentication(
        beneficiary.internal_record_id,
        vcType || undefined,
      );

      setAuthId(started.authentication_id);

      // The beneficiary authenticates at the identity provider, not here.
      // A centred popup mirrors the registry's own ID-authentication widget.
      const w = 1024;
      const h = 800;

      const left =
        window.screenX +
        Math.max(0, (window.outerWidth - w) / 2);

      const top =
        window.screenY +
        Math.max(0, (window.outerHeight - h) / 2);

      const popup = window.open(
        started.authorization_url,
        "beneficiary-auth",
        `popup=yes,width=${w},height=${h},left=${left},top=${top}`,
      );

      if (!popup) {
        setError(
          "The authentication window was blocked. Allow popups for this site and try again.",
        );

        setBusy(false);
        return;
      }

      popupRef.current = popup;
      popup.focus?.();

      stopPolling();

      const startedAt = Date.now();

      pollRef.current = window.setInterval(
        async () => {
          // Give up rather than poll forever.
          if (Date.now() - startedAt > POLL_TIMEOUT_MS) {
            stopPolling();

            setError(
              "Authentication timed out. Ask the beneficiary to try again.",
            );

            return;
          }

          try {
            const s = await api.authenticationStatus(
              beneficiary.internal_record_id,
              started.authentication_id,
            );

            setStatus(s);

            if (s.authorised) {
              stopPolling();

              popupRef.current?.close?.();

              setStage("issue");

              return;
            }
          } catch {
            // Transient error; the next tick retries.
          }

          // Closed without success.
          if (popupRef.current?.closed) {
            stopPolling();

            setError(
              "The authentication window was closed before it completed.",
            );
          }
        },
        2000,
      );
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  }

  /**
   * Existing Inji Certify issuance flow.
   */
  async function onIssue() {
    if (!beneficiary) return;

    setBusy(true);
    setError("");

    try {
      const { blob, filename, issuanceId } = await api.issue(
        beneficiary.internal_record_id,
        authId,
        vcType || undefined,
      );

      // Hand the file to the browser so the agent can print it.
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;

      document.body.appendChild(a);
      a.click();
      a.remove();

      URL.revokeObjectURL(url);

      setIssued({
        filename,
        issuanceId,
      });

      setStage("done");
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  }

  /**
   * New CredIssuer issuance flow.
   *
   * The backend performs:
   *
   * 1. Beneficiary authentication validation
   * 2. Registry lookup
   * 3. CredIssuer issuance
   * 4. Credential lookup
   * 5. PDF presentation generation
   * 6. PDF download
   */
  async function onCredIssuerIssue(CREDISSUER_CREDENTIAL_TEMPLATE: string,) {
    if (!beneficiary) return;

    setBusy(true);
    setError("");

    try {
      const {
        blob,
        filename,
        issuanceId,
      } = await api.issueWithCredIssuer(
        beneficiary.internal_record_id,
        authId,
        vcType || undefined,
        CREDISSUER_CREDENTIAL_TEMPLATE,
      );

      // Download the PDF returned by the backend.
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;

      document.body.appendChild(a);
      a.click();
      a.remove();

      URL.revokeObjectURL(url);

      setIssued({
        filename,
        issuanceId,
      });

      setStage("done");
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card-stack">
      <section className="card">
        <h2>1 · Find the beneficiary</h2>

        {/* The credential is chosen HERE, not at the issue step. */}
        {vcTypes.length > 1 && (
          <label>
            Credential

            <select
              value={vcType}
              onChange={(e) => setVcType(e.target.value)}
              disabled={busy || stage !== "lookup"}
            >
              {vcTypes.map((t) => (
                <option
                  key={t.config_id}
                  value={t.config_id}
                >
                  {t.display_name ?? t.config_id}
                </option>
              ))}
            </select>
          </label>
        )}

        <form onSubmit={onLookup} className="row">
          <input
            aria-label="National ID"
            placeholder="National ID"
            value={nationalId}
            onChange={(e) => setNationalId(e.target.value)}
            disabled={busy || stage !== "lookup"}
            autoFocus
          />

          <button
            type="submit"
            disabled={
              busy ||
              !nationalId.trim() ||
              stage !== "lookup"
            }
          >
            Look up
          </button>
        </form>

        {beneficiary && (
          <dl className="facts">
            <dt>Record</dt>
            <dd>
              {beneficiary.record_name ??
                beneficiary.internal_record_id}
            </dd>

            <dt>Status</dt>
            <dd>
              {beneficiary.eligible
                ? "Eligible"
                : (
                  beneficiary.reason ??
                  "Not eligible"
                )}
            </dd>
          </dl>
        )}
      </section>

      <section
        className="card"
        aria-disabled={stage === "lookup"}
      >
        <h2>2 · Beneficiary authenticates</h2>

        <p className="muted">
          The beneficiary authenticates themselves — by fingerprint
          at this counter, or with a one-time code sent to their phone.
          A credential cannot be issued without it.
        </p>

        <button
          onClick={onAuthenticate}
          disabled={
            busy ||
            !beneficiary?.eligible ||
            stage === "lookup"
          }
        >
          {authId
            ? "Restart authentication"
            : "Start authentication"}
        </button>

        {status && (
          <p
            className={
              status.authorised
                ? "ok"
                : "pending"
            }
          >
            {status.authorised
              ? `Authenticated — ${status.expires_in_seconds}s remaining to issue`
              : `Waiting… (${status.status})${
                  status.reason
                    ? ` — ${status.reason}`
                    : ""
                }`}
          </p>
        )}
      </section>

      <section
        className="card"
        aria-disabled={
          stage !== "issue" &&
          stage !== "done"
        }
      >
        <h2>3 · Issue and print</h2>

        <button
          onClick={onIssue}
          disabled={
            busy ||
            stage !== "issue"
          }
        >
          Download credential
        </button>

        <h2>Credential via CredIssuer</h2>

        <button
          onClick={() => onCredIssuerIssue("E37907852E73")}
          disabled={
            busy ||
            stage !== "issue"
          }
        >
          Issue with CredIssuer & Download
        </button>
        <button
          onClick={() => onCredIssuerIssue("2CC71027B1BE")}
          disabled={
            busy ||
            stage !== "issue"
          }
        >
        Land Record
        </button>

        {issued && (
          <p className="ok">
            Downloaded{" "}
            <strong>{issued.filename}</strong>.
            Print it and hand it to the beneficiary.

            <br />

            <span className="muted">
              Issuance {issued.issuanceId}
            </span>
          </p>
        )}
      </section>

      {error && (
        <p
          className="error"
          role="alert"
        >
          {error}
        </p>
      )}

      {(beneficiary || error) && (
        <button
          className="link"
          onClick={reset}
        >
          Start over
        </button>
      )}
    </div>
  );
}
