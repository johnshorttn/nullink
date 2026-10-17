package cloud.nullverse.nullinkphone

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** User-approved, view-only Android display relay. Frames are never written to disk. */
class PhoneScreenService : Service() {
    companion object {
        const val ACTION_START = "cloud.nullverse.nullinkphone.START_SCREEN"
        const val ACTION_STOP = "cloud.nullverse.nullinkphone.STOP_SCREEN"
        const val EXTRA_RESULT_CODE = "projection_result_code"
        const val EXTRA_RESULT_DATA = "projection_result_data"
        private const val CHANNEL_ID = "nullink_phone_screen"
        private const val NOTIFICATION_ID = 8403
        private const val MAX_EDGE = 1280
        private const val FRAME_INTERVAL_MS = 500L
    }

    private val prefs by lazy { getSharedPreferences("nullink_phone", MODE_PRIVATE) }
    private val stopping = AtomicBoolean(false)
    private val uploading = AtomicBoolean(false)
    private val uploader = Executors.newSingleThreadExecutor()
    private var projection: MediaProjection? = null
    private var display: VirtualDisplay? = null
    private var reader: ImageReader? = null
    private var captureThread: HandlerThread? = null
    private var lastFrameAt = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopCapture()
            return START_NOT_STICKY
        }
        if (projection != null) return START_NOT_STICKY
        val resultCode = intent?.getIntExtra(EXTRA_RESULT_CODE, 0) ?: 0
        val resultData = if (Build.VERSION.SDK_INT >= 33) {
            intent?.getParcelableExtra(EXTRA_RESULT_DATA, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent?.getParcelableExtra(EXTRA_RESULT_DATA)
        }
        if (resultCode != Activity.RESULT_OK || resultData == null || TokenVault.read(this) == null) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        createChannel()
        val notice = notification("Approved screen view is being sent to Nullink")
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notice, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
        } else {
            startForeground(NOTIFICATION_ID, notice)
        }
        try {
            val manager = getSystemService(MediaProjectionManager::class.java)
            val mediaProjection = manager.getMediaProjection(resultCode, resultData)
            projection = mediaProjection
            mediaProjection.registerCallback(object : MediaProjection.Callback() {
                override fun onStop() { stopCapture(projectionAlreadyStopped = true) }
            }, Handler(mainLooper))
            beginCapture(mediaProjection)
            prefs.edit().putBoolean("screen_mirroring", true).apply()
            notifyServer(true)
        } catch (_: Exception) {
            stopCapture()
        }
        return START_NOT_STICKY
    }

    private fun beginCapture(mediaProjection: MediaProjection) {
        val metrics = resources.displayMetrics
        val originalWidth = metrics.widthPixels.coerceAtLeast(1)
        val originalHeight = metrics.heightPixels.coerceAtLeast(1)
        val scale = minOf(1f, MAX_EDGE.toFloat() / maxOf(originalWidth, originalHeight))
        val width = (originalWidth * scale).toInt().coerceAtLeast(1)
        val height = (originalHeight * scale).toInt().coerceAtLeast(1)
        val density = metrics.densityDpi
        val thread = HandlerThread("nullink-screen-capture").apply { start() }
        captureThread = thread
        val handler = Handler(thread.looper)
        val imageReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
        reader = imageReader
        imageReader.setOnImageAvailableListener({ source ->
            val now = System.currentTimeMillis()
            if (now - lastFrameAt < FRAME_INTERVAL_MS || !uploading.compareAndSet(false, true)) {
                source.acquireLatestImage()?.close()
                return@setOnImageAvailableListener
            }
            val image = source.acquireLatestImage() ?: run { uploading.set(false); return@setOnImageAvailableListener }
            lastFrameAt = now
            try {
                val plane = image.planes[0]
                val paddedWidth = plane.rowStride / plane.pixelStride
                val raw = Bitmap.createBitmap(paddedWidth, image.height, Bitmap.Config.ARGB_8888)
                raw.copyPixelsFromBuffer(plane.buffer)
                val frame = if (paddedWidth == image.width) raw else Bitmap.createBitmap(raw, 0, 0, image.width, image.height).also { raw.recycle() }
                val jpeg = ByteArrayOutputStream().use { output ->
                    frame.compress(Bitmap.CompressFormat.JPEG, 58, output)
                    frame.recycle()
                    output.toByteArray()
                }
                uploader.execute {
                    try {
                        val base = prefs.getString("base_url", "") ?: ""
                        val token = TokenVault.read(this)
                        if (token != null && jpeg.size <= 768 * 1024) {
                            PhoneApi.request(base, "/api/phone/screen/frame", token, "PUT", jpeg,
                                mapOf("Content-Type" to "image/jpeg"), timeoutMs = 8_000)
                        }
                    } catch (_: Exception) {
                        // A later frame retries after transient network loss.
                    } finally { uploading.set(false) }
                }
            } catch (_: Exception) {
                uploading.set(false)
            } finally { image.close() }
        }, handler)
        display = mediaProjection.createVirtualDisplay(
            "Nullink Phone Screen", width, height, density,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, imageReader.surface, null, handler
        )
    }

    private fun notifyServer(active: Boolean) {
        val base = prefs.getString("base_url", "") ?: return
        val token = TokenVault.read(this) ?: return
        uploader.execute {
            try { PhoneApi.json(base, "/api/phone/screen/status", token, "POST", org.json.JSONObject().put("active", active)) }
            catch (_: Exception) { }
        }
    }

    private fun stopCapture(projectionAlreadyStopped: Boolean = false) {
        if (!stopping.compareAndSet(false, true)) return
        prefs.edit().putBoolean("screen_mirroring", false).apply()
        try { display?.release() } catch (_: Exception) { }
        display = null
        try { reader?.setOnImageAvailableListener(null, null); reader?.close() } catch (_: Exception) { }
        reader = null
        try { captureThread?.quitSafely() } catch (_: Exception) { }
        captureThread = null
        if (!projectionAlreadyStopped) try { projection?.stop() } catch (_: Exception) { }
        projection = null
        notifyServer(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Phone screen mirroring", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notification(text: String): Notification {
        val stop = PendingIntent.getService(this, 43, Intent(this, PhoneScreenService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL_ID) else Notification.Builder(this)
        return builder.setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle("Nullink screen sharing")
            .setContentText(text)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop mirroring", stop).build())
            .build()
    }

    override fun onDestroy() {
        if (!stopping.get()) stopCapture()
        uploader.shutdown()
        super.onDestroy()
    }
}
