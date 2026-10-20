package io.nullink.jinxendwatch

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class ControlClient(
    private val baseUrl: String,
    private val token: String,
) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    private fun url(path: String): String =
        baseUrl.trimEnd('/') + path

    private fun auth(builder: Request.Builder): Request.Builder {
        if (token.isNotBlank()) {
            builder.header("Authorization", "Bearer $token")
            builder.header("X-Control-Token", token)
        }
        return builder
    }

    fun status(): JSONObject {
        val req = auth(Request.Builder().url(url("/api/chatgpt-end-watch/status")).get()).build()
        return execute(req)
    }

    fun start(): JSONObject {
        val body = "{}".toRequestBody("application/json".toMediaType())
        val req = auth(
            Request.Builder().url(url("/api/chatgpt-end-watch/start")).post(body)
        ).build()
        return execute(req)
    }

    fun stop(): JSONObject {
        val body = "{}".toRequestBody("application/json".toMediaType())
        val req = auth(
            Request.Builder().url(url("/api/chatgpt-end-watch/stop")).post(body)
        ).build()
        return execute(req)
    }

    private fun execute(req: Request): JSONObject {
        http.newCall(req).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw IllegalStateException("HTTP ${resp.code}: ${text.take(200)}")
            }
            return if (text.isBlank()) JSONObject() else JSONObject(text)
        }
    }
}
