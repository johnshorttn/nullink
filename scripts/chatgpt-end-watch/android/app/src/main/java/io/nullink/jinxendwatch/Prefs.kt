package io.nullink.jinxendwatch

import android.content.Context

class Prefs(ctx: Context) {
    private val sp = ctx.getSharedPreferences("jinx_end_watch", Context.MODE_PRIVATE)

    var baseUrl: String
        get() = sp.getString(KEY_BASE, BuildConfig.DEFAULT_BASE_URL)?.trim().orEmpty()
            .ifEmpty { BuildConfig.DEFAULT_BASE_URL }
        set(v) = sp.edit().putString(KEY_BASE, v.trim().trimEnd('/')).apply()

    var token: String
        get() = sp.getString(KEY_TOKEN, "")?.trim().orEmpty()
        set(v) = sp.edit().putString(KEY_TOKEN, v.trim()).apply()

    companion object {
        private const val KEY_BASE = "base_url"
        private const val KEY_TOKEN = "token"
    }
}
