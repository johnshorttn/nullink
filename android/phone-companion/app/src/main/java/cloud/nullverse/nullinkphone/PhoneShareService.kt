package cloud.nullverse.nullinkphone

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import androidx.documentfile.provider.DocumentFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.UUID
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class PhoneShareService : Service() {
    companion object {
        const val ACTION_START = "cloud.nullverse.nullinkphone.START_SHARE"
        const val ACTION_STOP = "cloud.nullverse.nullinkphone.STOP_SHARE"
        private const val CHANNEL_ID = "nullink_phone_share"
        private const val NOTIFICATION_ID = 8402
        private const val MAX_FILE_BYTES = 25 * 1024 * 1024
    }

    private val prefs by lazy { getSharedPreferences("nullink_phone", MODE_PRIVATE) }
    private val documentMap by lazy { getSharedPreferences("nullink_phone_documents", MODE_PRIVATE) }
    private var worker: ExecutorService? = null
    @Volatile private var running = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            running = false
            Thread {
                sendShareState(false)
                prefs.edit().putBoolean("sharing", false).apply()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelfResult(startId)
            }.start()
            return START_NOT_STICKY
        }
        if (!prefs.getBoolean("sharing", false) || TokenVault.read(this) == null) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        if (worker != null) return START_STICKY
        createChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        running = true
        worker = Executors.newSingleThreadExecutor()
        worker?.execute { commandLoop() }
        return START_STICKY
    }

    private fun commandLoop() {
        try {
            sendShareState(true)
            updateNotification("Shared folders are available to your active Nullink session")
            while (running && prefs.getBoolean("sharing", false)) {
                try {
                    val base = prefs.getString("base_url", "") ?: ""
                    val token = TokenVault.read(this) ?: break
                    val (status, response) = PhoneApi.request(base, "/api/phone/commands/next?wait=20", token,
                        timeoutMs = 35_000)
                    if (status == 401 || status == 403) {
                        prefs.edit().putBoolean("sharing", false).apply()
                        updateNotification("Phone pairing expired or revoked")
                        break
                    }
                    if (status !in 200..299) { Thread.sleep(2_000); continue }
                    val command = JSONObject(String(response, Charsets.UTF_8)).optJSONObject("command") ?: continue
                    handleCommand(base, token, command)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt(); break
                } catch (_: Exception) {
                    if (running) Thread.sleep(3_000)
                }
            }
        } finally {
            try { sendShareState(false) } catch (_: Exception) { }
            prefs.edit().putBoolean("sharing", false).apply()
            running = false
            updateNotification("Folder sharing stopped")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun sendShareState(enabled: Boolean) {
        val base = prefs.getString("base_url", "") ?: return
        val token = TokenVault.read(this) ?: return
        val roots = if (enabled) prefs.getString("roots", "[]") ?: "[]" else "[]"
        val payload = JSONObject().put("enabled", enabled).put("roots", JSONArray(roots))
        PhoneApi.json(base, "/api/phone/share", token, "POST", payload, 15_000)
    }

    private fun handleCommand(base: String, token: String, command: JSONObject) {
        val id = command.optString("id")
        val operation = command.optString("operation")
        val rootId = command.optString("root_id")
        val documentId = command.optString("document_id", "root")
        try {
            if (!id.matches(Regex("[a-f0-9]{32}"))) error("Bad request id")
            when (operation) {
                "list" -> {
                    val result = JSONObject().put("items", listFolder(rootId, documentId))
                    PhoneApi.json(base, "/api/phone/commands/$id/result", token, "POST", result)
                }
                "read" -> uploadRequestedFile(base, token, id, rootId, documentId)
                else -> error("Unsupported request")
            }
        } catch (_: Exception) {
            try {
                PhoneApi.json(base, "/api/phone/commands/$id/result", token, "POST", JSONObject().put("error", "phone_read_failed"))
            } catch (_: Exception) { }
        }
    }

    private fun listFolder(rootId: String, documentId: String): JSONArray {
        val treeUri = rootUri(rootId)
        val uri = if (documentId == "root") treeUri else lookupDocument(rootId, documentId)
        // Keep the tree URI context for descendants so providers that require
        // DocumentsContract tree URIs can enumerate nested directories.
        val directory = DocumentFile.fromTreeUri(this, uri)
        if (directory == null || !directory.isDirectory) error("Folder unavailable")
        val output = JSONArray()
        directory.listFiles().take(500).forEach { child ->
            val name = child.name ?: "Untitled"
            val childId = UUID.randomUUID().toString().replace("-", "")
            documentMap.edit().putString("$rootId:$childId", child.uri.toString()).apply()
            output.put(JSONObject()
                .put("id", childId)
                .put("name", name)
                .put("directory", child.isDirectory)
                .put("mime", child.type ?: "application/octet-stream")
                .put("size", if (child.isFile) child.length().coerceAtLeast(0) else 0))
        }
        return output
    }

    private fun uploadRequestedFile(base: String, token: String, requestId: String, rootId: String, documentId: String) {
        val uri = lookupDocument(rootId, documentId)
        val file = DocumentFile.fromSingleUri(this, uri) ?: error("File unavailable")
        if (!file.isFile) error("Not a file")
        val name = file.name ?: "phone-file"
        val mime = file.type ?: "application/octet-stream"
        val input = contentResolver.openInputStream(uri) ?: error("File could not be opened")
        val output = ByteArrayOutputStream()
        input.use { stream ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                if (output.size() + count > MAX_FILE_BYTES) error("File exceeds the 25 MB transfer limit")
                output.write(buffer, 0, count)
            }
        }
        val encodedName = Uri.encode(name)
        val (status, response) = PhoneApi.request(base, "/api/phone/commands/$requestId/file", token, "PUT", output.toByteArray(),
            mapOf("Content-Type" to "application/octet-stream", "X-Phone-File-Name" to encodedName,
                "X-Phone-File-Mime" to mime), timeoutMs = 45_000)
        if (status !in 200..299) error("Phone file transfer failed (${status}: ${String(response, Charsets.UTF_8)})")
    }

    private fun rootUri(rootId: String): Uri {
        val roots = JSONArray(prefs.getString("roots", "[]") ?: "[]")
        for (i in 0 until roots.length()) {
            val root = roots.optJSONObject(i) ?: continue
            if (root.optString("id") == rootId) return Uri.parse(root.getString("uri"))
        }
        error("Folder is no longer shared")
    }

    private fun lookupDocument(rootId: String, documentId: String): Uri {
        require(documentId.matches(Regex("[A-Za-z0-9_-]{1,128}"))) { "Bad document reference" }
        val raw = documentMap.getString("$rootId:$documentId", null) ?: error("File listing expired; refresh the folder")
        val uri = Uri.parse(raw)
        val root = rootUri(rootId)
        // SAF constructs these URIs only from documents returned under this root;
        // check the tree grant still exists before using the stored handle.
        val granted = contentResolver.persistedUriPermissions.any {
            it.uri == root && it.isReadPermission
        }
        if (!granted) error("Android folder permission was revoked")
        return uri
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Phone folder sharing", NotificationManager.IMPORTANCE_LOW))
        }
    }

    private fun buildNotification(text: String = "Sharing selected folders with Nullink"): Notification {
        val stopIntent = Intent(this, PhoneShareService::class.java).setAction(ACTION_STOP)
        val pending = PendingIntent.getService(this, 42, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL_ID) else Notification.Builder(this)
        return builder.setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("Nullink Phone Drive")
            .setContentText(text)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop sharing", pending).build())
            .build()
    }

    private fun updateNotification(text: String) {
        try { getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text)) } catch (_: Exception) { }
    }

    override fun onDestroy() {
        running = false
        worker?.shutdownNow()
        worker = null
        super.onDestroy()
    }
}
