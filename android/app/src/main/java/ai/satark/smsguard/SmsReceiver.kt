package ai.satark.smsguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

/**
 * Called by Android for every incoming SMS. The text is sent to SatarkAI on the laptop and the
 * verdict is shown as a notification. Nothing is sent anywhere else.
 */
class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        // A long SMS arrives in several parts; join them per sender.
        val bySender = parts.filterNotNull().groupBy { it.displayOriginatingAddress ?: "unknown" }
        val pending = goAsync()   // keep the receiver alive while the network call runs
        val store = Store(context)
        Thread {
            try {
                for ((sender, msgs) in bySender) {
                    val text = msgs.joinToString("") { it.displayMessageBody ?: "" }
                    if (text.isBlank()) continue
                    val time = msgs.first().timestampMillis
                    val item = try {
                        val r = SatarkClient.checkSms(store.serverUrl, store.pairingCode, sender, text, "$sender-$time-${text.hashCode()}")
                        val reasons = r.optJSONArray("reasons")
                        Checked(System.currentTimeMillis(), sender, text, r.optString("level"), r.optInt("score"),
                            r.optString("category"), if (reasons != null && reasons.length() > 0) reasons.getString(0) else null, null)
                    } catch (e: Exception) {
                        Log.w(TAG, "check failed", e)
                        Checked(System.currentTimeMillis(), sender, text, null, null, null, null, e.message ?: e.javaClass.simpleName)
                    }
                    store.add(item)
                    Notifier.show(context, item)
                    context.sendBroadcast(Intent(ACTION_UPDATED).setPackage(context.packageName))
                }
                // The laptop answered, so also send any SMS that could not be checked earlier.
                if (store.recent().firstOrNull()?.level != null) Retry.unchecked(context)
            } finally {
                pending.finish()
            }
        }.start()
    }

    companion object {
        const val TAG = "SatarkSms"
        const val ACTION_UPDATED = "ai.satark.smsguard.UPDATED"
    }
}
