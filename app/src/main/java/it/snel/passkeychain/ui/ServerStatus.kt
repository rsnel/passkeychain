package it.snel.passkeychain.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import it.snel.passkeychain.io.VaultSync
import it.snel.passkeychain.store.LiveSync

private val LedGreen = Color(0xFF1E9E5A)
private val LedYellow = Color(0xFFF2B705)
private val LedRed = Color(0xFFC62828)
private val LedGrey = Color(0xFF9E9E9E)

private fun colour(light: LiveSync.Light) = when (light) {
    LiveSync.Light.Ok -> LedGreen
    LiveSync.Light.Warning -> LedYellow
    LiveSync.Light.Offline -> LedRed
    LiveSync.Light.Off -> LedGrey
}

private fun word(light: LiveSync.Light) = when (light) {
    LiveSync.Light.Ok -> "in sync"
    LiveSync.Light.Warning -> "needs attention"
    LiveSync.Light.Offline -> "no connection"
    LiveSync.Light.Off -> "not set up"
}

/** The server status light in the top bar: green, yellow, red, or grey when live sync is off. */
@Composable
fun ServerLed(status: LiveSync.Status, onClick: () -> Unit) {
    IconButton(onClick = onClick, modifier = Modifier.semantics { contentDescription = "Server: ${word(status.light)}" }) {
        Box(
            Modifier.size(14.dp).clip(CircleShape).background(colour(status.light))
                .border(1.5.dp, MaterialTheme.colorScheme.surface.copy(alpha = 0.6f), CircleShape),
        )
    }
}

/** What the light means, the server's details, and what to do. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerSheet(
    status: LiveSync.Status,
    onDismiss: () -> Unit,
    onSyncNow: () -> Unit,
    onSetUp: () -> Unit,
    onTurnOff: () -> Unit,
    collections: List<VaultSync.Collection> = emptyList(),
    target: VaultSync.Collection? = null,
    onTarget: (VaultSync.Collection?) -> Unit = {},
    backupFirst: Boolean = true,
    onBackupFirst: (Boolean) -> Unit = {},
) {
    var choosing by remember { mutableStateOf(false) }
    if (choosing) AlertDialog(
        onDismissRequest = { choosing = false },
        title = { Text("Where new passkeys go") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "Passkeys created on this phone are added here. An organisation collection shares them with " +
                        "the organisation's other members, such as your main account.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(8.dp))
                (listOf<VaultSync.Collection?>(null) + collections).forEach { c ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onTarget(c); choosing = false }.padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = c?.id == target?.id, onClick = { onTarget(c); choosing = false })
                        Text(c?.label ?: "This account's own vault")
                    }
                }
                if (collections.isEmpty()) Text(
                    "This account is in no organisation with a collection (as far as the last sync saw).",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = { choosing = false }) { Text("Close") } },
    )
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).navigationBarsPadding().padding(horizontal = 24.dp).padding(bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(16.dp).clip(CircleShape).background(colour(status.light)))
                Spacer(Modifier.width(12.dp))
                Text("Live sync: ${word(status.light)}", style = MaterialTheme.typography.titleLarge)
            }
            if (status.light == LiveSync.Light.Off) {
                Text(
                    "Keep the passkeys on this phone and in your own Vaultwarden or Bitwarden server in step. " +
                        "New passkeys in the vault come to the phone; passkeys created on the phone go to the vault. Nothing is deleted.\n\n" +
                        "Consider a separate Bitwarden account just for passkeys: live sync keeps that account's vault key on the phone. " +
                        "Share them with your main account through an organisation that both accounts belong to.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(onClick = onSetUp, modifier = Modifier.fillMaxWidth()) { Text("Set up live sync") }
                return@Column
            }
            Text(status.message, style = MaterialTheme.typography.bodyLarge)
            if (status.time > 0) Text(
                "Checked " + java.text.DateFormat.getDateTimeInstance().format(status.time),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            for ((k, v) in status.stats) Row {
                Text(k, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.width(12.dp))
                Text(v, Modifier.weight(1.4f), style = MaterialTheme.typography.bodyMedium)
            }
            Text(
                "Green: in sync. Yellow: the server answered unexpectedly or wants you to sign in again. " +
                    "Red: the server can't be reached. It syncs when the app opens (at most every 5 minutes) and after you create a passkey.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Back up first", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "A new passkey goes to the vault before the site gets it. If the server can't be reached, it isn't created.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.width(12.dp))
                Switch(checked = backupFirst, onCheckedChange = onBackupFirst)
            }
            OutlinedButton(onClick = { choosing = true }, modifier = Modifier.fillMaxWidth()) {
                Text("New passkeys go to: " + (target?.label ?: "this account's vault"))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = onSyncNow, modifier = Modifier.weight(1f)) { Text("Sync now") }
                if (status.light == LiveSync.Light.Warning && status.stats["Needs"] == "sign in again")
                    OutlinedButton(onClick = onSetUp, modifier = Modifier.weight(1f)) { Text("Sign in again") }
            }
            OutlinedButton(onClick = onTurnOff, modifier = Modifier.fillMaxWidth()) {
                Text("Turn off live sync", color = MaterialTheme.colorScheme.error)
            }
        }
    }
}
