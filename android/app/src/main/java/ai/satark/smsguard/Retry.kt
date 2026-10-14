package ai.satark.smsguard

import android.content.Context
import android.content.Intent

/**
 * Messages that arrived while the laptop could not be reached are stored as "Not checked".
 * As soon as SatarkAI answers again they are sent once more, so no SMS is lost.
 */
object Retry {
    private val lock = Any()

    /** Re-checks every unchecked SMS. Runs on a background thread. Returns how many are now checked. */
    fun unchecked(context: Context): Int = synchronized(lock) {
        val store = Store(context)
        var done = 0
        for (item in store.recent().filter { it.level == null }) {
            val fixed = try {
                val r = SatarkClient.checkSms(store.serverUrl, store.pairingCode, item.sender, item.text,
                    "${item.sender}-${item.time}-${item.text.hashCode()}")
                val reasons = r.optJSONArray("reasons")
                item.copy(level = r.optString("level"), score = r.optInt("score"), category = r.optString("category"),
                    reason = if (reasons != null && reasons.length() > 0) reasons.getString(0) else null, error = null)
            } catch (e: Exception) {
                break   // still unreachable: try again later
            }
            store.replace(item, fixed)
            Notifier.show(context, fixed)
            done++
        }
        if (done > 0) context.sendBroadcast(Intent(SmsReceiver.ACTION_UPDATED).setPackage(context.packageName))
        done
    }
}
