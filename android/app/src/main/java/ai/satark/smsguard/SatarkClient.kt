package ai.satark.smsguard

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Talks to the SatarkAI app on the laptop. Runs on a background thread, never on the UI thread. */
object SatarkClient {
    private const val TIMEOUT_MS = 8000

    /** Sends one SMS to /api/ingest and returns SatarkAI's verdict. Throws on network or server errors. */
    fun checkSms(server: String, code: String, sender: String, text: String, ref: String): JSONObject {
        val body = JSONObject()
            .put("text", text.take(20000)).put("channel", "sms").put("sender", sender.take(320))
            .put("source", "sms-app").put("ref", ref.take(300))
        return request("$server/api/ingest", "POST", code, body.toString())
    }

    /** True when the laptop answers. Used by the "Test connection" button. */
    fun health(server: String): Boolean =
        request("$server/api/health", "GET", null, null).optString("status") == "ok"

    private fun request(url: String, method: String, code: String?, body: String?): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            if (code != null) conn.setRequestProperty("X-Satark-Token", code)
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (status !in 200..299) {
                val detail = runCatching { JSONObject(text).optString("detail") }.getOrNull()
                throw IllegalStateException(detail?.ifEmpty { null } ?: "SatarkAI answered $status")
            }
            return JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }
}
