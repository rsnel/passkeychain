package it.snel.passkeychain.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.layout.width
import it.snel.passkeychain.hybrid.TunnelDomains
import it.snel.passkeychain.hybrid.TunnelSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val SERVER_HELP = "https://github.com/rsnel/passkeychain/tree/main/server"

private fun describe(number: Int): String {
    if (number == TunnelDomains.NONE) return "None"
    val host = TunnelDomains.hostname(number)
    return TunnelDomains.operator(number)?.let { "$it ($host)" } ?: "$host (#$number)"
}

/** The tunnel server settings: a first choice, and one for when that cannot be reached. */
@Composable
fun TunnelServerDialog(settings: TunnelSettings, onDismiss: () -> Unit) {
    var first by remember { mutableIntStateOf(settings.first) }
    var second by remember { mutableIntStateOf(settings.second) }
    var picking by remember { mutableIntStateOf(0) } // 0 none, 1 first, 2 second
    val uri = LocalUriHandler.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Tunnel server") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "Phone and computer meet on this server when you sign in with a QR code. " +
                        "Sign-ins are encrypted end to end: the server only sees that a connection happens.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Choice("First choice", describe(first)) { picking = 1 }
                Choice("If that can't be reached", describe(second)) { picking = 2 }
                TextButton(onClick = { uri.openUri(SERVER_HELP) }, modifier = Modifier.align(Alignment.Start)) {
                    Text("How to run your own server")
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                settings.first = first
                settings.second = if (second == first) TunnelDomains.NONE else second
                onDismiss()
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )

    if (picking != 0) TunnelPicker(
        allowNone = picking == 2,
        onPick = { n -> if (picking == 1) first = n else second = n; picking = 0 },
        onDismiss = { picking = 0 },
    )
}

@Composable
private fun Choice(label: String, value: String, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = Color.Transparent, // the dialog is surfaceContainerHigh already: an outline sets it apart
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

/**
 * Every server the app can use: the public ones browsers know by number
 * (Google, Apple), then all 65280 computed names, by top-level domain and
 * then alphabetically. Typing a number shows that number's name, so it can be
 * checked against the domain you registered; typing text narrows the list.
 */
@Composable
private fun TunnelPicker(allowNone: Boolean, onPick: (Int) -> Unit, onDismiss: () -> Unit) {
    var query by remember { mutableStateOf("") }
    // 65280 SHA-256 hashes and a sort: off the main thread, once
    val all by produceState<List<TunnelDomains.Entry>?>(null) {
        value = withContext(Dispatchers.Default) { TunnelDomains.all }
    }
    // the platform's dialog width is too narrow for the names: use the screen, less a margin
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(
            shape = RoundedCornerShape(28.dp),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp).fillMaxHeight(0.85f),
        ) {
            Column(Modifier.padding(top = 20.dp, start = 20.dp, end = 20.dp, bottom = 8.dp)) {
                Text("Choose a tunnel server", style = MaterialTheme.typography.headlineSmall)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Number or part of the name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                val entries = all
                if (entries == null) {
                    Box(Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                } else {
                    val shown = remember(entries, query) { TunnelDomains.search(query, entries) }
                    val public = shown.filter { it.number < TunnelDomains.FIRST_COMPUTED }
                    val computed = shown.filter { it.number >= TunnelDomains.FIRST_COMPUTED }
                    val number = query.trim().removePrefix("#").toIntOrNull()
                    if (number != null || shown.isEmpty()) Text(
                        when {
                            number != null && shown.isEmpty() ->
                                "Public servers are 0 to ${TunnelDomains.PUBLIC.size - 1}, own servers 256 to 65535."
                            number != null -> "Check that this is the name you registered."
                            else -> "No name contains \"${query.trim()}\"."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    LazyColumn(Modifier.weight(1f).fillMaxSize()) {
                        if (allowNone && query.isBlank()) item(key = "none") {
                            PickerRow("None", "no second choice", mono = false) { onPick(TunnelDomains.NONE) }
                        }
                        if (public.isNotEmpty()) {
                            item(key = "h-public") { Header("Public servers", "known to browsers by number") }
                            items(public, key = { it.number }) { e ->
                                PickerRow("${TunnelDomains.operator(e.number)} · ${e.host}", "#${e.number}", mono = false) { onPick(e.number) }
                            }
                        }
                        if (computed.isNotEmpty()) {
                            item(key = "h-own") { Header("For your own server", "%,d names".format(computed.size)) }
                            items(computed, key = { it.number }) { e ->
                                PickerRow(e.host, "#${e.number}", mono = true) { onPick(e.number) }
                            }
                        }
                    }
                }
                TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun Header(title: String, note: String) {
    Column(Modifier.fillMaxWidth().padding(top = 14.dp, bottom = 4.dp, start = 4.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text(note, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun PickerRow(title: String, note: String, mono: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            title,
            Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (mono) FontFamily.Monospace else null,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.width(8.dp))
        Text(note, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
