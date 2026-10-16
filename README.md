# Burp Extension — seefish-envelope

Enables the **tool-based manual option** for the vulnerable-seefish lab. The API
wraps every protected request in a custom RC4 envelope
`{ sid, alg:"RC4", data }`, so raw Burp traffic is opaque ciphertext. This
extension makes the envelope transparent for Repeater, Intruder, Proxy and
sqlmap:

| Behaviour | What it does |
|---|---|
| **On response** | `POST /api/session/key` → records the plaintext `sessionId`/`key` pair (this is also your F04d evidence, visible in Proxy history). |
| **On response** | Enveloped responses are decrypted and replaced with plaintext JSON, so every tool sees readable data. |
| **On request** | Any `POST /api/*` JSON body that is NOT already an envelope is sealed automatically with the recorded key. |
| **Pass-through** | Requests that are already envelopes (replays, bit-flip tampering) are left untouched — exactly what F04 needs. |

**Crypto note (white-box):** the implementation mirrors the lab's
`shared/protocol/rc4.js` exactly — the "key" is the base64 key *string* used as
UTF-8 text bytes (the lab does NOT base64-decode it first), standard KSA + PRGA,
no 256-byte drop, fresh keystream per message.

## Build (on the tester's machine)

Requirements: JDK 17+ and Gradle (or use Maven with the same dependency).

```bash
cd pentest-report/manual/burp-extension
gradle jar        # or: ./gradlew jar if you have a wrapper
# -> build/libs/seefish-envelope.jar
```

## Load

1. Burp Suite → **Extensions** tab → **Installed** → **Add**
2. Extension type: **Java**, select `seefish-envelope.jar`
3. The **Output** tab shows `[seefish-envelope] loaded`.

## Use

1. In **Repeater**, send `POST /api/session/key` to `http://127.0.0.1:3000`
   (empty body). Output logs `captured key for sid …`.
2. From now on, type **plain JSON** in Repeater/Intruder bodies — the
   extension seals them on the wire and opens the responses:
   - Login: `{"username":"bob","password":"StudentPass!23"}`
   - SQLi (F01): `{"token":"TOKEN","q":"x' OR 1=1 -- "}`
   - SSRF (F02): `{"token":"TOKEN","equipmentId":1,"target":"http://lab-device:8080/api/admin"}`
3. For **F04 replay/tamper**: use Proxy history (raw envelope), resend with
   **Ctrl+R** or edit `data` bytes in hex view — envelopes pass through
   untouched.

## Notes

- Status: reference implementation, source provided — this lab environment has
  no Java toolchain, so it is built/loaded on the tester's Burp host. The RC4
  logic is byte-identical to the lab's `rc4.js` (verified against the same
  sources used by the scripted PoCs).
- The extension was **not** used to produce the original findings (direct
  protocol access via the scripted PoCs did that); it exists to support
  tool-based reproduction.
