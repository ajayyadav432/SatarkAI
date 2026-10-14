package ai.satark.smsguard

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/** Phone notifications for checked SMS. Risky ones are high priority so they pop up on screen. */
object Notifier {
    private const val CH_RISK = "risk"
    private const val CH_INFO = "info"

    fun createChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_RISK, "Scam warnings", NotificationManager.IMPORTANCE_HIGH)
            .apply { description = "An incoming SMS looks like a scam" })
        nm.createNotificationChannel(NotificationChannel(CH_INFO, "Checked messages", NotificationManager.IMPORTANCE_LOW)
            .apply { description = "An incoming SMS was checked and looks safe, or could not be checked" })
    }

    fun show(context: Context, item: Checked) {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            android.os.Build.VERSION.SDK_INT >= 33) return
        val risky = item.level in setOf("Medium", "High", "Critical")
        val title = when {
            item.level == null -> "SatarkAI could not check an SMS"
            risky -> "⚠ ${item.level} risk SMS (${item.score}/100)"
            else -> "✓ SMS looks ${item.level?.lowercase()} (${item.score}/100)"
        }
        val detail = when {
            item.level == null -> "From ${item.sender}: ${item.error}"
            risky -> listOfNotNull(item.category?.takeIf { it != "None" }, item.reason).joinToString(" · ") +
                "\nFrom ${item.sender}. Do not click links, call back or share OTPs."
            else -> "From ${item.sender}"
        }
        val open = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = NotificationCompat.Builder(context, if (risky) CH_RISK else CH_INFO)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(detail.lineSequence().first())
            .setStyle(NotificationCompat.BigTextStyle().bigText(detail))
            .setPriority(if (risky) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_LOW)
            .setColor(0xFF059669.toInt())
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(context).notify(item.time.toInt(), n)
    }
}
