package cloud.nullverse.nullinkphone

import android.Manifest
import android.app.Activity
import android.media.projection.MediaProjectionManager
import android.media.projection.MediaProjectionConfig
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.ViewGroup
import android.text.InputFilter
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import androidx.documentfile.provider.DocumentFile
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val io = Executors.newSingleThreadExecutor()
    private val prefs by lazy { getSharedPreferences("nullink_phone", MODE_PRIVATE) }
    private lateinit var baseField: EditText
    private lateinit var pairCodeField: EditText
    private lateinit var deviceNameField: EditText
    private lateinit var rootsBox: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var shareSwitch: Switch
    private lateinit var screenStatusText: TextView
    private val pickTree = 7001
    private lateinit var controlStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        renderRoots()
        shareSwitch.isChecked = prefs.getBoolean("sharing", false)
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 90)
        }
    }

    private fun buildUi() {
        val outer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(20, 18, 20, 20) }
        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(TextView(this).apply { text = "Nullink Phone"; textSize = 25f; setPadding(0, 0, 0, 8) })
        content.addView(TextView(this).apply {
            text = "Share selected folders with your Nullink VPS session. Access is read-only and file bytes are sent only when requested."
            textSize = 14f; setPadding(0, 0, 0, 16)
        })
        baseField = field("Nullink HTTPS URL", prefs.getString("base_url", "https://nullink.216.158.238.236.sslip.io") ?: "")
        content.addView(baseField)
        deviceNameField = field("Device name", prefs.getString("device_name", "Pixel phone (awake)") ?: "Pixel phone (awake)")
        content.addView(deviceNameField)
        pairCodeField = field("Six-digit one-time pairing code", "").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(6))
        }
        content.addView(pairCodeField)
        content.addView(button("Pair with Nullink") { pairDevice() })
        content.addView(button("Add shared folder") { chooseFolder() })
        rootsBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 10, 0, 10) }
        content.addView(rootsBox)
        shareSwitch = Switch(this).apply {
            text = "Share selected folders while this service is active"
            setOnCheckedChangeListener { _, checked -> if (checked) startSharing() else stopSharing() }
        }
        content.addView(shareSwitch)
        content.addView(TextView(this).apply {
            text = "Screen mirroring sends a low-resolution live view to your signed-in Nullink session. Android asks for permission each time. While mirroring runs, Nullink Phone keeps the display awake (at a dim level) so it does not time out. This uses extra battery. Pressing the power button still turns the display off."
            textSize = 13f; setPadding(0, 18, 0, 4)
        })
        content.addView(button("Start screen mirroring") { requestScreenCapture() })
        content.addView(button("Stop screen mirroring") { stopScreenCapture() })
        screenStatusText = TextView(this).apply {
            text = if (prefs.getBoolean("screen_mirroring", false)) "Screen mirroring may be active." else "Screen mirroring is off."
            textSize = 13f; setPadding(0, 6, 0, 12)
        }
        content.addView(screenStatusText)
        controlStatus = TextView(this).apply { textSize = 14f }
        content.addView(controlStatus)
        content.addView(TextView(this).apply {
            text = "Remote control is optional. Manually enable Nullink Phone Control in Android Accessibility Settings, start mirroring, then allow control for this session. Your signed-in browser can tap, swipe, and navigate. Locked screens and protected dialogs cannot be controlled. Rotate the phone only after stopping mirroring; restart to use the new orientation."
        })
        content.addView(button("Open Accessibility Settings") {
            startActivity(Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS))
        })
        content.addView(button("Allow remote control for this session") {
            PhoneControlService.allowed = PhoneControlService.instance != null && PhoneControlService.session != null
            updateControlStatus()
        })
        content.addView(button("Stop remote control") {
            PhoneControlService.stopControl(); updateControlStatus()
        })
        content.addView(TextView(this).apply {
            text = "Android shows a persistent notification with a Stop control while mirroring. Stopping mirroring releases the keep-awake lock. If you turn the display off manually, the service continues but the live picture may go blank."
            textSize = 13f; setPadding(0, 10, 0, 12)
        })
        statusText = TextView(this).apply { text = "Not paired"; textSize = 14f }
        content.addView(statusText)
        content.addView(button("Unpair this phone") { unpair() })
        scroll.addView(content)
        outer.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        setContentView(outer)
        val paired = TokenVault.read(this) != null
        statusText.text = if (paired) "Paired · sharing is off" else "Not paired"
        shareSwitch.isEnabled = paired
    }

    private fun field(label: String, value: String): EditText = EditText(this).apply {
        hint = label; setText(value); textSize = 15f
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun button(label: String, action: () -> Unit): Button = Button(this).apply {
        text = label; setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun normalizedBase(): String {
        val base = baseField.text.toString().trim().trimEnd('/')
        require(base.startsWith("https://", ignoreCase = true)) { "Enter the HTTPS Nullink address." }
        return base
    }

    private fun pairDevice() {
        val base = try { normalizedBase() } catch (e: Exception) { statusText.text = e.message; return }
        val code = pairCodeField.text.toString().trim()
        if (code.isBlank()) { statusText.text = "Enter the code shown in Nullink Phone Drive."; return }
        statusText.text = "Pairing…"
        io.execute {
            try {
                val payload = JSONObject().put("code", code).put("name", deviceNameField.text.toString().trim())
                val result = PhoneApi.json(base, "/api/phone/pair", method = "POST", body = payload)
                val token = result.getString("token")
                TokenVault.save(this, token)
                prefs.edit().putString("base_url", base).putString("device_id", result.getJSONObject("device").getString("id"))
                    .putString("device_name", deviceNameField.text.toString().trim()).apply()
                runOnUiThread {
                    pairCodeField.setText(""); shareSwitch.isEnabled = true
                    statusText.text = "Paired securely. Add folders, then turn sharing on."
                }
            } catch (e: Exception) {
                val message = when (e.message) {
                    "pair_rate_limited" -> "Too many pairing attempts from this network. Wait five minutes and generate a fresh code."
                    "invalid_or_expired_pairing_code", "invalid_pairing_code" -> "That pairing code is invalid or expired. Generate a new code in Nullink."
                    else -> e.message ?: "Pairing failed."
                }
                runOnUiThread { statusText.text = message }
            }
        }
    }

    private fun chooseFolder() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).addFlags(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
        )
        startActivityForResult(intent, pickTree)
    }

    @Deprecated("The system directory picker result is handled through the activity result callback.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == pickScreen && resultCode == RESULT_OK && data != null) {
            val intent = Intent(this, PhoneScreenService::class.java)
                .setAction(PhoneScreenService.ACTION_START)
                .putExtra(PhoneScreenService.EXTRA_RESULT_CODE, resultCode)
                .putExtra(PhoneScreenService.EXTRA_RESULT_DATA, data)
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
            prefs.edit().putBoolean("screen_mirroring", true).apply()
            if (::screenStatusText.isInitialized) screenStatusText.text = "Screen mirroring is active. Keep the phone unlocked while viewing."
            return
        }
        if (requestCode != pickTree || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        try {
            val readFlag = data.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION
            contentResolver.takePersistableUriPermission(uri, readFlag)
            val dir = DocumentFile.fromTreeUri(this, uri) ?: error("Folder could not be opened")
            val roots = readRoots()
            val alreadySelected = (0 until roots.length()).any { index ->
                roots.optJSONObject(index)?.optString("uri") == uri.toString()
            }
            if (alreadySelected) {
                statusText.text = "That folder is already selected."; return
            }
            roots.put(JSONObject().put("id", UUID.randomUUID().toString().replace("-", ""))
                .put("name", dir.name ?: "Shared folder").put("uri", uri.toString()))
            writeRoots(roots)
            renderRoots()
            statusText.text = "Folder added. Only its listing moves during browsing; file contents are read on request."
        } catch (e: Exception) { statusText.text = e.message ?: "Could not save folder access." }
    }

    private fun readRoots(): JSONArray = try { JSONArray(prefs.getString("roots", "[]")) } catch (_: Exception) { JSONArray() }
    private fun writeRoots(roots: JSONArray) { prefs.edit().putString("roots", roots.toString()).apply() }

    private fun renderRoots() {
        if (!::rootsBox.isInitialized) return
        rootsBox.removeAllViews()
        val roots = readRoots()
        if (roots.length() == 0) rootsBox.addView(TextView(this).apply { text = "No folders selected yet." })
        for (i in 0 until roots.length()) {
            val root = roots.optJSONObject(i) ?: continue
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL }
            row.addView(TextView(this).apply { text = "📁 ${root.optString("name")}"; textSize = 14f },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            row.addView(Button(this).apply { text = "Remove"; setOnClickListener { removeRoot(root.optString("id")) } })
            rootsBox.addView(row)
        }
    }

    private fun removeRoot(rootId: String) {
        if (shareSwitch.isChecked) { statusText.text = "Stop folder sharing before changing its folder grants."; return }
        val old = readRoots(); val kept = JSONArray()
        for (i in 0 until old.length()) old.optJSONObject(i)?.let {
            if (it.optString("id") != rootId) kept.put(it)
            else try {
                contentResolver.releasePersistableUriPermission(
                    Uri.parse(it.optString("uri")), Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } catch (_: Exception) { }
        }
        writeRoots(kept); renderRoots(); clearDocumentMap(rootId)
        statusText.text = "Folder removed from this companion. Android permission remains only if another app grant uses it."
    }

    private fun startSharing() {
        if (TokenVault.read(this) == null) { shareSwitch.isChecked = false; statusText.text = "Pair this phone first."; return }
        if (readRoots().length() == 0) { shareSwitch.isChecked = false; statusText.text = "Select at least one folder."; return }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            shareSwitch.isChecked = false
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 90)
            statusText.text = "Allow notifications so the active folder sharing indicator and Stop control stay visible."
            return
        }
        val base = try { normalizedBase() } catch (e: Exception) { shareSwitch.isChecked = false; statusText.text = e.message; return }
        prefs.edit().putString("base_url", base).putBoolean("sharing", true).apply()
        startSharingService(); statusText.text = "Sharing is on. Android will keep a visible notification until you stop it."
    }

    private fun stopSharing() {
        prefs.edit().putBoolean("sharing", false).apply()
        startService(Intent(this, PhoneShareService::class.java).setAction(PhoneShareService.ACTION_STOP))
        statusText.text = "Sharing stopped. The server will refuse any new folder reads."
    }

    private fun startSharingService() {
        val intent = Intent(this, PhoneShareService::class.java).setAction(PhoneShareService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }

    private fun requestScreenCapture() {
        if (TokenVault.read(this) == null) {
            screenStatusText.text = "Pair this phone with Nullink first."
            return
        }
        val base = try { normalizedBase() } catch (e: Exception) {
            screenStatusText.text = e.message ?: "Enter the HTTPS Nullink address."
            return
        }
        prefs.edit().putString("base_url", base).apply()
        val manager = getSystemService(MediaProjectionManager::class.java)
        val captureIntent = if (Build.VERSION.SDK_INT >= 34) {
            manager.createScreenCaptureIntent(MediaProjectionConfig.createConfigForDefaultDisplay())
        } else {
            manager.createScreenCaptureIntent()
        }
        startActivityForResult(captureIntent, pickScreen)
    }

    private fun stopScreenCapture() {
        startService(Intent(this, PhoneScreenService::class.java).setAction(PhoneScreenService.ACTION_STOP))
        prefs.edit().putBoolean("screen_mirroring", false).apply()
        if (::screenStatusText.isInitialized) screenStatusText.text = "Screen mirroring stopped."
    }

    private fun unpair() {
        stopScreenCapture()
        if (shareSwitch.isChecked) shareSwitch.isChecked = false
        val token = TokenVault.read(this)
        val base = prefs.getString("base_url", "") ?: ""
        val deviceId = prefs.getString("device_id", "") ?: ""
        io.execute {
            if (token != null && deviceId.matches(Regex("[a-f0-9]{32}"))) {
                try { PhoneApi.request(base, "/api/phone/devices/$deviceId", token, "DELETE") } catch (_: Exception) { }
            }
            TokenVault.clear(this)
            runOnUiThread { shareSwitch.isEnabled = false; statusText.text = "Unpaired. Generate a new code in Nullink to connect again." }
        }
    }

    private fun clearDocumentMap(rootId: String) {
        val map = getSharedPreferences("nullink_phone_documents", MODE_PRIVATE)
        map.all.keys.filter { it.startsWith("$rootId:") }.forEach { map.edit().remove(it).apply() }
    }

    private fun updateControlStatus() {
        if (::controlStatus.isInitialized) controlStatus.text = when {
            PhoneControlService.instance == null -> "Control disabled: manually enable Nullink Phone Control in Accessibility Settings."
            PhoneControlService.session == null -> "Accessibility enabled. Start screen mirroring before allowing control."
            PhoneControlService.allowed -> "REMOTE CONTROL ACTIVE. Use Stop remote control or Stop mirroring to end it."
            else -> "Accessibility enabled. Remote control is OFF until you allow this session."
        }
    }
    override fun onResume() { super.onResume(); updateControlStatus() }

    override fun onDestroy() { super.onDestroy(); io.shutdown() }

    companion object { private const val pickScreen = 7002 }
}
