package it.snel.passkeychain.ui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import it.snel.passkeychain.BuildConfig
import it.snel.passkeychain.camera.QrScanActivity
import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.io.KeePassXc
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.store.PasskeyStore
import it.snel.passkeychain.ui.theme.PassKeyChainTheme
import it.snel.passkeychain.update.UpdateChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = PasskeyStore(applicationContext)
        setContent { PassKeyChainTheme { MainScreen(store) } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(store: PasskeyStore) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var passkeys by remember { mutableStateOf(listOf<Passkey>()) }
    var menuOpen by remember { mutableStateOf(false) }
    var updateDialog by remember { mutableStateOf<UpdateChecker.Status?>(null) }
    var scanInfo by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) { passkeys = withContext(Dispatchers.IO) { store.load() } }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                runCatching {
                    val text = ctx.contentResolver.openInputStream(uri)!!.use { it.readBytes().toString(Charsets.UTF_8) }
                    val res = KeePassXc.parse(text)
                    res.imported.forEach { store.upsert(it) }
                    passkeys = store.load()
                    "Imported ${res.imported.size}" + if (res.skipped.isNotEmpty()) ", skipped ${res.skipped.size}" else ""
                }.getOrElse { "Import failed: ${it.message}" }
            }
            snackbar.showSnackbar(msg)
        }
    }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                runCatching {
                    val text = KeePassXc.export(store.load())
                    ctx.contentResolver.openOutputStream(uri)!!.use { it.write(text.toByteArray()) }
                    "Exported ${store.load().size} passkeys"
                }.getOrElse { "Export failed: ${it.message}" }
            }
            snackbar.showSnackbar(msg)
        }
    }
    val scanLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        val qr = res.data?.getStringExtra(QrScanActivity.RESULT_QR) ?: return@rememberLauncherForActivityResult
        scanInfo = if (FidoQr.isFidoQr(qr)) {
            runCatching {
                val f = FidoQr.parse(qr)
                "Recognized a FIDO hybrid QR (operation: ${f.hint}).\n\n" +
                    "The key material is ready and the assertion is signed locally. " +
                    "Completing the sign-in over the BLE proximity tunnel is the on-device " +
                    "stage still being wired up (see hybrid/HybridTransport.kt)."
            }.getOrElse { "FIDO QR, but could not decode: ${it.message}" }
        } else "Scanned a non-FIDO QR:\n\n${qr.take(120)}"
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("PassKeyChain") },
                actions = {
                    IconButton(onClick = { menuOpen = true }) { Icon(Icons.Default.MoreVert, "Menu") }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(text = { Text("Import (KeePassXC JSON)") }, onClick = {
                            menuOpen = false; importLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                        }, leadingIcon = { Icon(Icons.Default.FileDownload, null) })
                        DropdownMenuItem(text = { Text("Export") }, onClick = {
                            menuOpen = false; exportLauncher.launch("passkeychain-export.json")
                        }, leadingIcon = { Icon(Icons.Default.FileUpload, null) })
                        DropdownMenuItem(text = { Text("Check for updates") }, onClick = {
                            menuOpen = false
                            scope.launch { updateDialog = UpdateChecker(ctx).check() }
                        }, leadingIcon = { Icon(Icons.Default.SystemUpdate, null) })
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                text = { Text("Scan QR to sign in") },
                icon = { Icon(Icons.Default.QrCodeScanner, null) },
                onClick = { scanLauncher.launch(Intent(ctx, QrScanActivity::class.java)) },
            )
        },
    ) { padding ->
        if (passkeys.isEmpty()) {
            EmptyState(Modifier.padding(padding))
        } else {
            LazyColumn(Modifier.padding(padding).fillMaxSize(), contentPadding = PaddingValues(12.dp)) {
                items(passkeys, key = { it.credentialId + it.rpId }) { pk ->
                    PasskeyRow(pk, onDelete = {
                        scope.launch {
                            passkeys = withContext(Dispatchers.IO) { store.delete(pk.credentialId, pk.rpId) }
                            snackbar.showSnackbar("Deleted ${pk.label}")
                        }
                    })
                }
            }
        }
    }

    updateDialog?.let { status ->
        UpdateDialog(status, onDismiss = { updateDialog = null }, onInstall = { rel ->
            scope.launch {
                runCatching { UpdateChecker(ctx).downloadAndInstall(rel) }
                    .onFailure { snackbar.showSnackbar("Update failed: ${it.message}") }
                updateDialog = null
            }
        })
    }
    scanInfo?.let { info ->
        AlertDialog(
            onDismissRequest = { scanInfo = null },
            confirmButton = { TextButton(onClick = { scanInfo = null }) { Text("OK") } },
            title = { Text("Cross-device sign-in") },
            text = { Text(info) },
        )
    }
}

@Composable
private fun EmptyState(modifier: Modifier = Modifier) {
    Column(modifier.fillMaxSize().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center) {
        Icon(Icons.Default.Key, null, Modifier.size(72.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(16.dp))
        Text("No passkeys yet", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "Use the menu to import a KeePassXC passkey export (JSON). " +
                "Imported keys are encrypted at rest with an Android Keystore key.",
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun PasskeyRow(pk: Passkey, onDelete: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Key, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(pk.label, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(pk.rpName.ifBlank { pk.rpId }, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "Delete", tint = MaterialTheme.colorScheme.error) }
        }
    }
}

@Composable
private fun UpdateDialog(status: UpdateChecker.Status, onDismiss: () -> Unit, onInstall: (UpdateChecker.Release) -> Unit) {
    val (title, body, rel) = when (status) {
        is UpdateChecker.Status.UpToDate -> Triple("Up to date", "You are on the latest ${BuildConfig.UPDATE_CHANNEL} build (${BuildConfig.VERSION_NAME}).", null)
        is UpdateChecker.Status.Available -> Triple("Update available", status.release.notes.ifBlank { status.release.tag }, status.release)
        is UpdateChecker.Status.Error -> Triple("Update check failed", status.message, null)
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            if (rel != null) TextButton(onClick = { onInstall(rel) }) { Text("Install") }
            else TextButton(onClick = onDismiss) { Text("OK") }
        },
        dismissButton = { if (rel != null) TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

