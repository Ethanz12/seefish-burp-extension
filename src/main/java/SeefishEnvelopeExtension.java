/*
 * SeefishEnvelopeExtension — Burp Suite (Montoya API) extension for the
 * vulnerable-seefish lab.
 *
 * The lab API wraps every protected request in a custom RC4 envelope:
 *   { "sid": "<sessionId>", "alg": "RC4", "data": "<base64(RC4(key, JSON))>" }
 * Raw Burp Repeater/Intruder traffic therefore shows opaque ciphertext and
 * cannot be edited meaningfully. This extension makes the envelope
 * transparent:
 *
 *   - RESPONSES: when POST /api/session/key returns {sessionId, key} (the
 *     plaintext handshake), the key is recorded. Enveloped responses are then
 *     decrypted and replaced with their plaintext JSON, so every tool sees
 *     readable data.
 *   - REQUESTS: any POST /api/* JSON body that is NOT already an envelope is
 *     sealed automatically using the recorded key. Repeater, Intruder and
 *     sqlmap (via --proxy) can then work with PLAIN JSON.
 *
 * Requests that are already envelopes (replays / bit-flip tampering) pass
 * through untouched, which is exactly what F04 needs.
 *
 * RC4 implementation mirrors the lab's shared/protocol/rc4.js exactly:
 *   - the "key" is the base64 key STRING used as UTF-8 text bytes (the lab
 *     normalizes the key string, it does NOT base64-decode it first);
 *   - standard KSA + PRGA, no 256-byte drop, fresh keystream per message.
 *
 * Build:  gradle jar   (see build.gradle / README.md)
 * Load:   Burp -> Extensions -> Add -> select seefish-envelope.jar
 */

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SeefishEnvelopeExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.logging().logToOutput("[seefish-envelope] loaded — seals/opens RC4 envelopes for the vulnerable-seefish lab");
        api.http().registerHttpHandler(new SeefishHttpHandler(api));
    }
}

class SeefishHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    // session id -> key (captured from the plaintext handshake)
    private final Map<String, String> sidToKey = new ConcurrentHashMap<>();
    // host -> most recent session id
    private final Map<String, String> hostToSid = new ConcurrentHashMap<>();

    private static final Pattern ENVELOPE_REQ = Pattern.compile("\"alg\"\\s*:\\s*\"RC4\"");
    private static final Pattern ENV_PARTS =
            Pattern.compile("\"sid\"\\s*:\\s*\"([^\"]+)\".*?\"data\"\\s*:\\s*\"([^\"]+)\"", Pattern.DOTALL);
    private static final Pattern KEY_PARTS =
            Pattern.compile("\"sessionId\"\\s*:\\s*\"([^\"]+)\".*?\"key\"\\s*:\\s*\"([^\"]+)\"", Pattern.DOTALL);

    SeefishHttpHandler(MontoyaApi api) {
        this.api = api;
    }

    // ------------------------------------------------------------------
    // Requests: seal any plain-JSON POST to /api/* using the recorded key.
    // ------------------------------------------------------------------
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        try {
            String path = req.path();
            String method = req.method();
            if (path == null || !path.startsWith("/api/")) return null;
            if (method == null || !"POST".equalsIgnoreCase(method)) return null;
            String body = req.bodyToString();
            if (body == null || !body.trim().startsWith("{")) return null;
            if (ENVELOPE_REQ.matcher(body).find()) return null; // replay/tamper: leave as-is

            String host = req.headerValue("Host");
            String sid = host == null ? null : hostToSid.get(host);
            if (sid == null) {
                api.logging().logToOutput("[seefish-envelope] no key for host " + host
                        + " — send POST /api/session/key first (or replay any sealed request)");
                return null;
            }
            String key = sidToKey.get(sid);
            if (key == null) return null;

            String sealed = seal(sid, key, body);
            api.logging().logToOutput("[seefish-envelope] sealed " + path + " (sid " + sid + ")");
            return RequestToBeSentAction.continueWith(req.withBody(ByteArray.byteArray(sealed)));
        } catch (Exception e) {
            api.logging().logToError("[seefish-envelope] request handler error: " + e);
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Responses: record handshake keys, decrypt enveloped responses.
    // ------------------------------------------------------------------
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived res) {
        try {
            String body = res.bodyToString();
            if (body == null || !body.contains("\"alg\"") && !body.contains("\"sessionId\"")) return null;

            // Plaintext handshake: capture sid -> key (leave visible: F04d evidence).
            Matcher km = KEY_PARTS.matcher(body);
            if (km.find()) {
                String sid = km.group(1);
                String key = km.group(2);
                sidToKey.put(sid, key);
                HttpRequest init = res.initiatingRequest();
                if (init != null) {
                    String host = init.headerValue("Host");
                    if (host != null) hostToSid.put(host, sid);
                }
                api.logging().logToOutput("[seefish-envelope] captured key for sid " + sid
                        + " (plaintext handshake — F04d evidence)");
                return null;
            }

            // Enveloped response: decrypt in place.
            Matcher em = ENV_PARTS.matcher(body);
            if (!em.find()) return null;
            String sid = em.group(1);
            String data = em.group(2);
            String key = sidToKey.get(sid);
            if (key == null) return null;

            String opened = open(key, data);
            api.logging().logToOutput("[seefish-envelope] opened response for sid " + sid);
            HttpResponse modified = res.withBody(ByteArray.byteArray(opened))
                    .withUpdatedHeader("Content-Type", "application/json");
            return ResponseReceivedAction.continueWith(modified);
        } catch (Exception e) {
            api.logging().logToError("[seefish-envelope] response handler error: " + e);
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Lab RC4 (mirrors shared/protocol/rc4.js): key = UTF-8 of the base64
    // key STRING, KSA + PRGA, no drop, fresh keystream per message.
    // ------------------------------------------------------------------
    private static byte[] rc4(byte[] keyBytes, byte[] data) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (keyBytes[i % keyBytes.length] & 0xff)) & 0xff;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        int i = 0;
        j = 0;
        byte[] out = new byte[data.length];
        for (int n = 0; n < data.length; n++) {
            i = (i + 1) & 0xff;
            j = (j + s[i]) & 0xff;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            out[n] = (byte) (data[n] ^ s[(s[i] + s[j]) & 0xff]);
        }
        return out;
    }

    private static String seal(String sid, String keyB64, String payload) {
        byte[] k = keyB64.getBytes(StandardCharsets.UTF_8);
        byte[] c = rc4(k, payload.getBytes(StandardCharsets.UTF_8));
        return "{\"sid\":\"" + sid + "\",\"alg\":\"RC4\",\"data\":\""
                + Base64.getEncoder().encodeToString(c) + "\"}";
    }

    private static String open(String keyB64, String dataB64) {
        byte[] k = keyB64.getBytes(StandardCharsets.UTF_8);
        byte[] p = rc4(k, Base64.getDecoder().decode(dataB64));
        return new String(p, StandardCharsets.UTF_8);
    }
}
