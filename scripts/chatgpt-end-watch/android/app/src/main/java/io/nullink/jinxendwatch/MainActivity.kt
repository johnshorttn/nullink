package io.nullink.jinxendwatch

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private val scope = CoroutineScope(Dispatchers.Main + Job())
    private lateinit var prefs: Prefs

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        prefs = Prefs(this)

        val inputBase = findViewById<TextInputEditText>(R.id.inputBaseUrl)
        val inputToken = findViewById<TextInputEditText>(R.id.inputToken)
        val txtStatus = findViewById<TextView>(R.id.txtStatus)
        inputBase.setText(prefs.baseUrl)
        inputToken.setText(prefs.token)

        findViewById<Button>(R.id.btnSave).setOnClickListener {
            prefs.baseUrl = inputBase.text?.toString().orEmpty()
            prefs.token = inputToken.text?.toString().orEmpty()
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            refreshStatus(txtStatus)
        }
        findViewById<Button>(R.id.btnOverlayPerm).setOnClickListener {
            requestOverlayPermission()
        }
        findViewById<Button>(R.id.btnShowOverlay).setOnClickListener {
            if (!Settings.canDrawOverlays(this)) {
                Toast.makeText(this, "Overlay permission required", Toast.LENGTH_LONG).show()
                requestOverlayPermission()
                return@setOnClickListener
            }
            prefs.baseUrl = inputBase.text?.toString().orEmpty()
            prefs.token = inputToken.text?.toString().orEmpty()
            val i = Intent(this, OverlayService::class.java).setAction(OverlayService.ACTION_SHOW)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(i)
            } else {
                startService(i)
            }
        }
        findViewById<Button>(R.id.btnHideOverlay).setOnClickListener {
            startService(
                Intent(this, OverlayService::class.java).setAction(OverlayService.ACTION_HIDE)
            )
        }
        refreshStatus(txtStatus)
    }

    private fun requestOverlayPermission() {
        val uri = Uri.parse("package:$packageName")
        startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, uri))
    }

    private fun refreshStatus(txt: TextView) {
        scope.launch {
            txt.text = "Status: loading…"
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    ControlClient(prefs.baseUrl, prefs.token).status()
                }
            }
            txt.text = result.fold(
                onSuccess = {
                    val armed = it.optBoolean("armed", it.optBoolean("active"))
                    "Status: armed=$armed updated=${it.optString("updated_at")}\n$it"
                },
                onFailure = { "Status error: ${it.message}" }
            )
        }
    }
}
