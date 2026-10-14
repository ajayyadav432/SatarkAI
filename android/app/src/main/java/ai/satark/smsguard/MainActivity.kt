package ai.satark.smsguard

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import ai.satark.smsguard.theme.SatarkAISMSGuardTheme
import java.text.DateFormat
import java.util.Date

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Notifier.createChannels(this)
        enableEdgeToEdge()
        setContent {
            SatarkAISMSGuardTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { HomeScreen() }
            }
        }
    }
}

private val LEVEL_COLOR = mapOf(
    "Safe" to Color(0xFF16A34A), "Low" to Color(0xFF8A8FA3), "Medium" to Color(0xFFF5A524),
    "High" to Color(0xFFF07A4A), "Critical" to Color(0xFFDC3545),
)
private val EMERALD = Color(0xFF059669)

private fun permissionsNeeded(): Array<String> =
    if (Build.VERSION.SDK_INT >= 33) arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.POST_NOTIFICATIONS)
    else arrayOf(Manifest.permission.RECEIVE_SMS)

@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val store = remember { Store(context) }
    var server by remember { mutableStateOf(store.serverUrl) }
    var code by remember { mutableStateOf(store.pairingCode) }
    var recent by remember { mutableStateOf(store.recent()) }
    var status by remember { mutableStateOf("") }
    fun granted() = permissionsNeeded().all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }
    var allowed by remember { mutableStateOf(granted()) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { allowed = granted() }

    // Refresh the list when a new SMS has been checked.
    DisposableEffect(Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) { recent = store.recent() }
        }
        ContextCompat.registerReceiver(context, receiver, IntentFilter(SmsReceiver.ACTION_UPDATED), ContextCompat.RECEIVER_NOT_EXPORTED)
        onDispose { context.unregisterReceiver(receiver) }
    }

    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.background(EMERALD, RoundedCornerShape(10.dp)).padding(horizontal = 10.dp, vertical = 6.dp)) {
                Text("🛡", fontSize = 18.sp)
            }
            Spacer(Modifier.width(10.dp))
            Column {
                Text("SatarkAI SMS Guard", fontWeight = FontWeight.Bold, fontSize = 20.sp)
                Text("Every incoming SMS is checked automatically", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (!allowed) {
            Button(onClick = { ask.launch(permissionsNeeded()) }, modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = EMERALD)) { Text("Allow SMS and notifications") }
        } else {
            Text("✓ Protection is on", color = EMERALD, fontWeight = FontWeight.SemiBold)
        }

        OutlinedTextField(value = server, onValueChange = { server = it; store.serverUrl = it }, singleLine = true,
            label = { Text("SatarkAI address (laptop)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = code, onValueChange = { code = it; store.pairingCode = it }, singleLine = true,
            label = { Text("Pairing code") }, modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(onClick = {
                status = "Checking…"
                Thread {
                    val ok = runCatching { SatarkClient.health(store.serverUrl) }.getOrDefault(false)
                    (context as? ComponentActivity)?.runOnUiThread { status = if (ok) "✓ Connected" else "✗ Cannot reach the laptop" }
                }.start()
            }) { Text("Test connection") }
            Spacer(Modifier.width(12.dp))
            Text(status, fontSize = 14.sp)
        }

        Text("Recently checked", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        if (recent.isEmpty()) {
            Text("No SMS checked yet. New messages appear here.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 14.sp)
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(recent) { RecentCard(it) }
        }
    }
}

@Composable
private fun RecentCard(item: Checked) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                val color = LEVEL_COLOR[item.level] ?: Color.Gray
                Box(Modifier.background(color, RoundedCornerShape(50)).padding(horizontal = 10.dp, vertical = 2.dp)) {
                    Text(if (item.level != null) "${item.level} ${item.score}" else "Not checked", color = Color.White,
                        fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
                Spacer(Modifier.width(8.dp))
                Text(item.sender, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, modifier = Modifier.weight(1f))
                Text(DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(item.time)), fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(item.text, maxLines = 2, overflow = TextOverflow.Ellipsis, fontSize = 14.sp)
            val note = item.error ?: listOfNotNull(item.category?.takeIf { it != "None" }, item.reason).joinToString(" · ")
            if (note.isNotEmpty()) Text(note, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
