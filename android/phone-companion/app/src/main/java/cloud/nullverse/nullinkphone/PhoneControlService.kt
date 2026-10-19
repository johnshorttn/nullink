package cloud.nullverse.nullinkphone

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.app.KeyguardManager
import android.graphics.Path
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** No window content retrieval, text access, shell, or automatic permission grants. */
class PhoneControlService : AccessibilityService() {
    companion object {
        @Volatile var instance: PhoneControlService? = null
            private set
        @Volatile var session: String? = null
        @Volatile var allowed = false
        @Volatile var captureWidth = 0
        @Volatile var captureHeight = 0

        fun stopControl() { allowed = false }
        fun execute(command: JSONObject): Boolean {
            val service = instance ?: return false
            val done = CountDownLatch(1)
            var success = false
            Handler(Looper.getMainLooper()).post {
                try {
                    if (!allowed || session == null || command.optString("session") != session ||
                        command.optLong("expires_at") < System.currentTimeMillis() ||
                        command.optLong("expires_at") > System.currentTimeMillis() + 4000 ||
                        service.getSystemService(KeyguardManager::class.java).isKeyguardLocked) {
                        done.countDown(); return@post
                    }
                    val size = android.graphics.Point()
                    @Suppress("DEPRECATION")
                    service.getSystemService(android.view.WindowManager::class.java).defaultDisplay.getRealSize(size)
                    // A rotated or resized capture must be restarted before accepting input.
                    if (size.x != captureWidth || size.y != captureHeight) {
                        allowed = false; done.countDown(); return@post
                    }
                    val c = command.getJSONObject("command")
                    val action = c.getString("action")
                    val fields = when (action) {
                        "tap" -> setOf("action", "x", "y")
                        "swipe" -> setOf("action", "x", "y", "end_x", "end_y", "duration_ms")
                        "back", "home", "recents" -> setOf("action")
                        else -> emptySet()
                    }
                    require(fields.isNotEmpty() && c.keys().asSequence().toSet() == fields)
                    if (action in setOf("back", "home", "recents")) {
                        success = service.performGlobalAction(when (action) {
                            "back" -> GLOBAL_ACTION_BACK
                            "home" -> GLOBAL_ACTION_HOME
                            else -> GLOBAL_ACTION_RECENTS
                        })
                        done.countDown(); return@post
                    }
                    fun coordinate(key: String, extent: Int): Float {
                        require(c.get(key) is Number)
                        val n = c.getDouble(key)
                        require(n.isFinite() && n in 0.0..1.0)
                        return (n * (extent - 1)).toFloat()
                    }
                    val path = Path().apply { moveTo(coordinate("x", size.x), coordinate("y", size.y)) }
                    val duration = if (action == "swipe") {
                        require(c.get("duration_ms") is Int)
                        c.getLong("duration_ms").also { require(it in 100..1000) }
                    } else 50L
                    if (action == "swipe") path.lineTo(coordinate("end_x", size.x), coordinate("end_y", size.y))
                    val gesture = GestureDescription.Builder().addStroke(GestureDescription.StrokeDescription(path, 0, duration)).build()
                    if (!service.dispatchGesture(gesture, object : GestureResultCallback() {
                        override fun onCompleted(gestureDescription: GestureDescription) { success = true; done.countDown() }
                        override fun onCancelled(gestureDescription: GestureDescription) { done.countDown() }
                    }, null)) done.countDown()
                } catch (_: Exception) { done.countDown() }
            }
            return done.await(2, TimeUnit.SECONDS) && success
        }
    }
    override fun onServiceConnected() { instance = this; allowed = false }
    override fun onAccessibilityEvent(event: AccessibilityEvent?) { }
    override fun onInterrupt() { allowed = false }
    override fun onUnbind(intent: android.content.Intent?): Boolean { instance = null; allowed = false; return super.onUnbind(intent) }
    override fun onDestroy() { instance = null; allowed = false; super.onDestroy() }
}
