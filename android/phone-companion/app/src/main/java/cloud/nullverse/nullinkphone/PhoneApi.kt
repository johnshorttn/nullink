package cloud.nullverse.nullinkphone

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

internal object PhoneApi {
    fun request(baseUrl: String, path: String, token: String? = null, method: String = "GET", body: ByteArray? = null,
                headers: Map<String, String> = emptyMap(), timeoutMs: Int = 15_000): Pair<Int, ByteArray> {
        val base = baseUrl.trim().trimEnd('/')
        require(base.startsWith("https://", ignoreCase = true)) { "Use an HTTPS Nullink URL." }
        val connection = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            useCaches = false
            setRequestProperty("Accept", "application/json")
            token?.let { setRequestProperty("Authorization", "Bearer $it") }
            headers.forEach { (key, value) -> setRequestProperty(key, value) }
            if (body != null) {
                doOutput = true
                if (method == "PUT") setFixedLengthStreamingMode(body.size)
                else setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
        }
        try {
            if (body != null) connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            return status to bytes
        } finally {
            connection.disconnect()
        }
    }

    fun json(baseUrl: String, path: String, token: String? = null, method: String = "GET", body: JSONObject? = null,
             timeoutMs: Int = 15_000): JSONObject {
        val bytes = body?.toString()?.toByteArray(Charsets.UTF_8)
        val (status, payload) = request(baseUrl, path, token, method, bytes, timeoutMs = timeoutMs)
        val parsed = try { JSONObject(String(payload, Charsets.UTF_8)) } catch (_: Exception) { JSONObject() }
        if (status !in 200..299) throw IllegalStateException(parsed.optString("error", "Nullink request failed ($status)"))
        return parsed
    }
}
