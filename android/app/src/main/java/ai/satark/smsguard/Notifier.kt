package ai.satark.smsguard

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap

/** Phone notifications for checked SMS. Risky ones are high priority so they pop up on screen. */
object Notifier {
    private const val CH_RISK = "risk"
    private const val CH_INFO = "info"
    private const val HELPLINE = "1930"   // India's national cybercrime helpline

    private val LEVEL_COLOR = mapOf(
        "Safe" to 0xFF16A34A.toInt(), "Low" to 0xFF6B7280.toInt(), "Medium" to 0xFFF5A524.toInt(),
        "High" to 0xFFF07A4A.toInt(), "Critical" to 0xFFDC3545.toInt(),
    )

    fun createChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_RISK, "Scam warnings", NotificationManager.IMPORTANCE_HIGH)
            .apply { description = "An incoming SMS looks like a scam"; enableVibration(true) })
        nm.createNotificationChannel(NotificationChannel(CH_INFO, "Checked messages", NotificationManager.IMPORTANCE_LOW)
            .apply { description = "An incoming SMS was checked and looks safe, or could not be checked" })
    }

    /** If SatarkAI recommends blocking this sender (3+ risky messages), show a separate block notification. */
    fun maybeBlock(context: Context, response: org.json.JSONObject) {
        val b = response.optJSONObject("block") ?: return
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val sender = b.optString("sender")
        val count = b.optInt("count")
        val isPhone = b.optString("kind") == "phone"
        val builder = NotificationCompat.Builder(context, CH_RISK)
            .setSmallIcon(R.drawable.ic_stat_satark)
            .setLargeIcon(logo(context))
            .setColor(0xFFDC3545.toInt())
            .setContentTitle("⛔ Block $sender")
            .setContentText("Sent $count scam messages. SatarkAI recommends blocking.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "$sender has sent $count scam messages. SatarkAI recommends blocking it.\n" + b.optString("how")))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
        if (isPhone) {
            val block = PendingIntent.getActivity(context, sender.hashCode(),
                Intent(context, BlockActivity::class.java).putExtra(BlockActivity.EXTRA_NUMBER, sender),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            builder.setContentIntent(block).addAction(0, "Block number", block)
        }
        // One block notification per sender, replaced (not repeated) as the count grows.
        NotificationManagerCompat.from(context).notify(("block:" + sender).hashCode(), builder.build())
    }

    private fun logo(context: Context): Bitmap? =
        ContextCompat.getDrawable(context, R.drawable.ic_logo)?.toBitmap(192, 192)

    fun show(context: Context, item: Checked) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val risky = item.level in setOf("Medium", "High", "Critical")
        val category = item.category?.takeIf { it.isNotBlank() && it != "None" }

        val title: String
        val line: String
        val big: String
        when {
            item.level == null -> {
                title = "SatarkAI could not check an SMS"
                line = "From ${item.sender} · ${item.error}"
                big = "From ${item.sender}\n${item.error}\n\nOpen SatarkAI and tap \"Test connection\"."
            }
            risky -> {
                title = "⚠ Scam SMS · ${item.level} ${item.score}"
                line = listOfNotNull(item.ownLevel?.let { "alone: $it ${item.ownScore}" }, category, "from ${item.sender}")
                    .joinToString(" · ")
                big = buildString {
                    append(category ?: "Suspicious message").append(" · from ").append(item.sender)
                    if (item.ownLevel != null) {
                        append("\n\nThis message alone: ").append(item.ownLevel).append(" ").append(item.ownScore)
                        append("\nWith this sender's earlier messages: ").append(item.level).append(" ").append(item.score)
                    }
                    item.reason?.let { append("\n\nWhy: ").append(it) }
                    append("\n\nDo not click links, call back, pay or share an OTP.")
                    append("\nLost money? Call $HELPLINE now.")
                }
            }
            else -> {
                title = "✓ SMS looks ${item.level?.lowercase()} · ${item.score}"
                line = "From ${item.sender} · checked by SatarkAI"
                big = "From ${item.sender}\n${item.text.take(160)}"
            }
        }

        val open = PendingIntent.getActivity(context, 0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val builder = NotificationCompat.Builder(context, if (risky) CH_RISK else CH_INFO)
            .setSmallIcon(R.drawable.ic_stat_satark)
            .setLargeIcon(logo(context))
            .setColor(LEVEL_COLOR[item.level] ?: 0xFF059669.toInt())
            .setContentTitle(title)
            .setContentText(line)
            .setStyle(NotificationCompat.BigTextStyle().bigText(big).setBigContentTitle(title))
            .setPriority(if (risky) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_LOW)
            .setCategory(if (risky) NotificationCompat.CATEGORY_MESSAGE else NotificationCompat.CATEGORY_STATUS)
            .setWhen(item.time).setShowWhen(true)
            .setContentIntent(open)
            .setAutoCancel(true)
            .addAction(0, "View details", open)
        if (risky) {
            // Opens the dialer with 1930 filled in; the user still has to press call.
            val dial = PendingIntent.getActivity(context, 1, Intent(Intent.ACTION_DIAL, Uri.parse("tel:$HELPLINE")),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            builder.addAction(0, "Call $HELPLINE", dial)
        }
        NotificationManagerCompat.from(context).notify(item.time.toInt(), builder.build())
    }
}
