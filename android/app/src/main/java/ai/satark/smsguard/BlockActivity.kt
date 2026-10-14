package ai.satark.smsguard

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.telecom.TelecomManager
import android.widget.Toast

/**
 * Opened from the "Block number" button of a block notification. Android does not let ordinary apps
 * block numbers, so this copies the number and opens the phone's own "Blocked numbers" screen,
 * where the user pastes it and confirms.
 */
class BlockActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val number = intent.getStringExtra(EXTRA_NUMBER).orEmpty()
        if (number.isNotEmpty()) {
            getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("Number to block", number))
            Toast.makeText(this, "Copied $number. Tap Add and paste it to block.", Toast.LENGTH_LONG).show()
        }
        val opened = runCatching {
            startActivity(getSystemService(TelecomManager::class.java).createManageBlockedNumbersIntent())
        }.isSuccess || runCatching { startActivity(Intent(Settings.ACTION_SETTINGS)) }.isSuccess
        if (!opened) Toast.makeText(this, "Open your Phone app > Settings > Blocked numbers.", Toast.LENGTH_LONG).show()
        finish()
    }

    companion object {
        const val EXTRA_NUMBER = "number"
    }
}
