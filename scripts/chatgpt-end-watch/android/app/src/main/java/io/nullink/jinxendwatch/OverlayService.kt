package io.nullink.jinxendwatch

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * SYSTEM_ALERT_WINDOW floating panel with Start / Stop.
 * Talks to VPS control API: /api/chatgpt-end-watch/{start,stop,status}
 */
class OverlayService : Service() {
    private val scope = CoroutineScope(Dispatchers.Main + Job())
    private val handler = Handler(Looper.getMainLooper())
    private var wm: WindowManager? = null
    private var view: View? = null
    private var stateTv: TextView? = null
    private lateinit var prefs: Prefs

    private val pollRunnable = object : Runnable {
        override fun run() {
            refreshState()
            handler.postDelayed(this, 4000L)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        prefs = Prefs(this)
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_HIDE -> {
                teardown()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIF_ID, buildNotification())
                showOverlay()
                handler.removeCallbacks(pollRunnable)
                handler.post(pollRunnable)
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        handler.removeCallbacks(pollRunnable)
        teardown()
        super.onDestroy()
    }

    private fun showOverlay() {
        if (view != null) return
        wm = getSystemService(WINDOW_SERVICE) as WindowManager
        val inflater = getSystemService(LAYOUT_INFLATER_SERVICE) as LayoutInflater
        val v = inflater.inflate(R.layout.overlay_panel, null)
        stateTv = v.findViewById(R.id.overlayState)
        v.findViewById<Button>(R.id.btnOverlayStart).setOnClickListener { callApi("start") }
        v.findViewById<Button>(R.id.btnOverlayStop).setOnClickListener { callApi("stop") }

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        )
        params.gravity = Gravity.TOP or Gravity.START
        params.x = 40
        params.y = 180

        var dragX = 0
        var dragY = 0
        var startX = 0
        var startY = 0
        v.setOnTouchListener { _, ev ->
            when (ev.action) {
                MotionEvent.ACTION_DOWN -> {
                    dragX = params.x
                    dragY = params.y
                    startX = ev.rawX.toInt()
                    startY = ev.rawY.toInt()
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    params.x = dragX + (ev.rawX.toInt() - startX)
                    params.y = dragY + (ev.rawY.toInt() - startY)
                    wm?.updateViewLayout(v, params)
                    true
                }
                else -> false
            }
        }

        wm?.addView(v, params)
        view = v
        refreshState()
    }

    private fun teardown() {
        view?.let { runCatching { wm?.removeView(it) } }
        view = null
        stateTv = null
    }

    private fun client(): ControlClient = ControlClient(prefs.baseUrl, prefs.token)

    private fun callApi(action: String) {
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    when (action) {
                        "start" -> client().start()
                        else -> client().stop()
                    }
                }
            }
            result.fold(
                onSuccess = {
                    val active = it.optBoolean("active")
                    stateTv?.text = if (active) "RUNNING" else "STOPPED"
                    Toast.makeText(
                        this@OverlayService,
                        "$action ok active=$active",
                        Toast.LENGTH_SHORT
                    ).show()
                },
                onFailure = {
                    Toast.makeText(
                        this@OverlayService,
                        "$action failed: ${it.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            )
        }
    }

    private fun refreshState() {
        scope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { client().status() } }
            result.onSuccess {
                val active = it.optBoolean("active")
                val halt = it.optJSONObject("control")?.optBoolean("the_end_halt") == true
                stateTv?.text = when {
                    halt -> "HALTED (The End)"
                    active -> "RUNNING"
                    else -> "STOPPED"
                }
            }
        }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Overlay", NotificationManager.IMPORTANCE_LOW)
        )
    }

    private fun buildNotification(): Notification {
        val pending = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.overlay_notification))
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_SHOW = "io.nullink.jinxendwatch.SHOW"
        const val ACTION_HIDE = "io.nullink.jinxendwatch.HIDE"
        private const val CHANNEL = "jinx_end_watch_overlay"
        private const val NOTIF_ID = 4217
    }
}
