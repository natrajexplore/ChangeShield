# Testing instructions for judges

**Live demo:** `TODO https://<project>.web.app`. No login is needed, because the app signs you in anonymously.

## Requirements
- Chrome Desktop **139 or later** (Windows, macOS, Linux or ChromeOS).
- For the on-device path: open `chrome://flags/#prompt-api-for-gemini-nano-multimodal-input`, set it to **Enabled**, and restart Chrome. The first model download needs a few GB of free disk space and can take several minutes.
- Without Gemini Nano the app still works. Stage 1 shows **SKIPPED**, the rules and leak gate still protect secrets, and the audit runs in the cloud.

## 2-minute test
1. Open the demo and click **Prepare on-device model**. Wait for the chip to read `Gemini Nano: available`.
2. Click **Sample: Cisco IOS-XE**, then **Redact & audit**.
3. Watch the stage badges: `LOCAL · rules` → `ON-DEVICE · Gemini Nano` → `LOCAL · rules` (leak gate) → `CLOUD · Gemini`.
4. Expand **What the cloud model actually saw** and confirm there are no passwords, IPs, names or circuit IDs.
5. Toggle **Reveal real values (local only)** to see the originals restored in the browser.
6. Choose **Air-gapped**, click **Sample: PAN-OS**, and run it. Every stage should report on-device.
7. Click **Save sanitized report**, then open **Saved reports** to see the Firestore history.

## Run from source
See the [README](../README.md#run-it-locally). `npm test` runs the redaction engine's unit tests and needs no Firebase project.

## Notes
- App Check uses the **debug provider** on the judging build, which the contest rules accept.
- All sample data is fictitious: RFC 5737 documentation IPs and `.example` domains.
- The project stays free to use and unrestricted until the end of the Judging Period.
