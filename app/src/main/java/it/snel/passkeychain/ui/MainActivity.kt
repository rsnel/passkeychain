package it.snel.passkeychain.ui

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import it.snel.passkeychain.R
import it.snel.passkeychain.camera.QrScanActivity
import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.io.Bitwarden
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.store.PasskeyStore
import it.snel.passkeychain.store.UserUnlock
import androidx.fragment.app.FragmentActivity
import it.snel.passkeychain.ui.theme.PassKeyChainTheme
import it.snel.passkeychain.update.UpdateChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() { // FragmentActivity for the unlock prompt

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val store = PasskeyStore(applicationContext)
        setContent { PassKeyChainTheme { MainScreen(store) } }
    }
}

/** What the update dialog shows. */
private sealed interface UpdateUi {
    data object Checking : UpdateUi
    data class Result(val status: UpdateChecker.Status) : UpdateUi
    data class Downloading(val release: UpdateChecker.Release, val percent: Int) : UpdateUi
}

private data class ScanResult(val title: String, val text: String, val recognized: Boolean)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(store: PasskeyStore) {
    val ctx = LocalContext.current
    val activity = ctx as FragmentActivity
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val updater = remember { UpdateChecker(ctx) }
    var passkeys by remember { mutableStateOf(listOf<Passkey>()) }
    var loaded by remember { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<Passkey?>(null) }
    var update by remember { mutableStateOf<UpdateUi?>(null) }
    var scan by remember { mutableStateOf<ScanResult?>(null) }
    var about by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        passkeys = withContext(Dispatchers.IO) { store.load() }
        loaded = true
    }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                runCatching {
                    val text = ctx.contentResolver.openInputStream(uri)!!.use { it.readBytes().toString(Charsets.UTF_8) }
                    val res = Bitwarden.parse(text)
                    res.imported.forEach { store.upsert(it) }
                    passkeys = store.load()
                    val n = res.imported.size
                    (if (n == 1) "Imported 1 passkey" else "Imported $n passkeys") +
                        if (res.skipped.isNotEmpty()) ", skipped ${res.skipped.size}" else ""
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
                    val all = store.load()
                    ctx.contentResolver.openOutputStream(uri)!!.use { it.write(Bitwarden.export(all).toByteArray()) }
                    if (all.size == 1) "Exported 1 passkey" else "Exported ${all.size} passkeys"
                }.getOrElse { "Export failed: ${it.message}" }
            }
            snackbar.showSnackbar(msg)
        }
    }
    val scanLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        val qr = res.data?.getStringExtra(QrScanActivity.RESULT_QR) ?: return@rememberLauncherForActivityResult
        scan = if (FidoQr.isFidoQr(qr)) {
            runCatching {
                val f = FidoQr.parse(qr)
                ScanResult(
                    "Sign-in QR recognized",
                    "This is a passkey sign-in request (" +
                        (if (f.hint == "mc") "create a passkey" else "sign in with a passkey") +
                        ").\n\nSigning in on another device this way isn't supported yet.",
                    recognized = true,
                )
            }.getOrElse { ScanResult("Unreadable sign-in QR", "This looks like a passkey QR, but it could not be decoded: ${it.message}", false) }
        } else ScanResult("Not a sign-in QR", qr.take(160), false)
    }
    val openImport = { importLauncher.launch(arrayOf("application/json", "text/plain", "*/*")) }

    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val listState = rememberLazyListState()
    val fabExpanded by remember { derivedStateOf { listState.firstVisibleItemIndex == 0 } }

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            LargeTopAppBar(
                title = { Text("Passkeys") },
                scrollBehavior = scrollBehavior,
                colors = TopAppBarDefaults.largeTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                ),
                actions = {
                    IconButton(onClick = { menuOpen = true }) { Icon(Icons.Rounded.MoreVert, "More options") }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text("Import from Bitwarden") },
                            leadingIcon = { Icon(AppIcons.FileDownload, null) },
                            onClick = { menuOpen = false; openImport() },
                        )
                        DropdownMenuItem(
                            text = { Text("Export") },
                            leadingIcon = { Icon(AppIcons.FileUpload, null) },
                            enabled = passkeys.isNotEmpty(),
                            onClick = {
                                menuOpen = false
                                // the export contains every private key: confirm it's the owner first
                                UserUnlock.prompt(
                                    activity,
                                    title = "Export passkeys",
                                    description = "The export file contains all your private keys, unencrypted. Keep it safe and delete it when you no longer need it.",
                                    onSuccess = { exportLauncher.launch("passkeychain-bitwarden.json") },
                                    onError = { cancelled, message -> if (!cancelled) scope.launch { snackbar.showSnackbar(message) } },
                                )
                            },
                        )
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text("Check for updates") },
                            leadingIcon = { Icon(AppIcons.SystemUpdate, null) },
                            onClick = {
                                menuOpen = false
                                update = UpdateUi.Checking
                                scope.launch { update = UpdateUi.Result(updater.check()) }
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("About") },
                            leadingIcon = { Icon(Icons.Rounded.Info, null) },
                            onClick = { menuOpen = false; about = true },
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                text = { Text("Scan sign-in QR") },
                icon = { Icon(AppIcons.QrCodeScanner, null) },
                expanded = fabExpanded,
                onClick = { scanLauncher.launch(Intent(ctx, QrScanActivity::class.java)) },
            )
        },
    ) { padding ->
        when {
            !loaded -> Box(Modifier.fillMaxSize().padding(padding))
            passkeys.isEmpty() -> EmptyState(Modifier.padding(padding), onImport = openImport)
            else -> PasskeyList(passkeys, listState, padding, onClick = { selected = it })
        }
    }

    selected?.let { pk ->
        PasskeySheet(
            pk,
            onDismiss = { selected = null },
            onCopied = { scope.launch { snackbar.showSnackbar("Credential ID copied") } },
            onDelete = {
                selected = null
                scope.launch {
                    passkeys = withContext(Dispatchers.IO) { store.delete(pk.credentialId, pk.rpId) }
                    val r = snackbar.showSnackbar("Deleted passkey for ${pk.label}", actionLabel = "Undo", withDismissAction = true)
                    if (r == SnackbarResult.ActionPerformed) passkeys = withContext(Dispatchers.IO) { store.upsert(pk) }
                }
            },
        )
    }

    update?.let { u ->
        UpdateDialog(
            u, current = updater.currentLabel,
            onDismiss = { if (u !is UpdateUi.Downloading) update = null },
            onInstall = { rel ->
                update = UpdateUi.Downloading(rel, 0)
                scope.launch {
                    runCatching { updater.downloadAndInstall(rel) { p -> update = UpdateUi.Downloading(rel, p) } }
                        .onFailure { snackbar.showSnackbar("Update failed: ${it.message}") }
                    update = null
                }
            },
        )
    }

    scan?.let { s ->
        AlertDialog(
            onDismissRequest = { scan = null },
            icon = { Icon(AppIcons.QrCode2, null) },
            title = { Text(s.title) },
            text = { Text(s.text) },
            confirmButton = { TextButton(onClick = { scan = null }) { Text("OK") } },
        )
    }

    if (about) AboutDialog(updater.currentLabel, onDismiss = { about = false })
}

// ---- list -------------------------------------------------------------------

@Composable
private fun PasskeyList(
    passkeys: List<Passkey>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    padding: PaddingValues,
    onClick: (Passkey) -> Unit,
) {
    val groups = remember(passkeys) {
        passkeys.groupBy { it.rpId }.toSortedMap(String.CASE_INSENSITIVE_ORDER)
    }
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(
            start = 16.dp, end = 16.dp,
            top = padding.calculateTopPadding() + 4.dp,
            bottom = padding.calculateBottomPadding() + 104.dp, // room for the FAB
        ),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        item(key = "summary") { SummaryCard(passkeys.size) }
        groups.forEach { (rpId, items) ->
            item(key = "h:$rpId") {
                val name = items.first().rpName.ifBlank { rpId }
                Row(Modifier.padding(start = 16.dp, top = 20.dp, bottom = 8.dp), verticalAlignment = Alignment.Bottom) {
                    Text(name, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
                    if (name != rpId) {
                        Text(
                            "  $rpId", style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
            items(items, key = { "p:${it.rpId}:${it.credentialId}" }) { pk ->
                val i = items.indexOf(pk)
                PasskeyItem(pk, segmentShape(i, items.size), onClick = { onClick(pk) })
            }
        }
    }
}

/** Rounded outer corners for a group, small inner corners: the "segmented list" look. */
private fun segmentShape(index: Int, count: Int): RoundedCornerShape {
    val big = 20.dp; val small = 4.dp
    val top = if (index == 0) big else small
    val bottom = if (index == count - 1) big else small
    return RoundedCornerShape(topStart = top, topEnd = top, bottomStart = bottom, bottomEnd = bottom)
}

@Composable
private fun SummaryCard(count: Int) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.primaryContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(48.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center,
            ) { Icon(AppIcons.Shield, null, tint = MaterialTheme.colorScheme.onPrimary) }
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    if (count == 1) "1 passkey" else "$count passkeys",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
                Text(
                    "Encrypted with the Android Keystore. Private keys never leave this phone.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
                )
            }
        }
    }
}

@Composable
private fun PasskeyItem(pk: Passkey, shape: RoundedCornerShape, onClick: () -> Unit) {
    Surface(shape = shape, color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.fillMaxWidth()) {
        ListItem(
            modifier = Modifier.clickable(onClick = onClick),
            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            leadingContent = { SiteAvatar(pk) },
            headlineContent = { Text(pk.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
            supportingContent = {
                val sub = pk.userDisplayName.takeIf { it.isNotBlank() && it != pk.label } ?: pk.rpId
                Text(sub, maxLines = 1, overflow = TextOverflow.Ellipsis)
            },
            trailingContent = { Icon(AppIcons.ChevronRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) },
        )
    }
}

/** A coloured circle with the site's initial; the hue is derived from the rpId so it is stable. */
@Composable
internal fun SiteAvatar(pk: Passkey, size: Dp = 40.dp) {
    val dark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val hue = ((pk.rpId.hashCode() % 360) + 360) % 360
    val bg = Color.hsl(hue.toFloat(), 0.55f, if (dark) 0.32f else 0.86f)
    val fg = Color.hsl(hue.toFloat(), 0.60f, if (dark) 0.88f else 0.25f)
    val initial = (pk.rpName.ifBlank { pk.rpId.removePrefix("www.").removePrefix("login.") }).take(1).uppercase()
    Box(Modifier.size(size).clip(CircleShape).background(bg), contentAlignment = Alignment.Center) {
        Text(initial, color = fg, style = if (size > 48.dp) MaterialTheme.typography.headlineSmall else MaterialTheme.typography.titleMedium)
    }
}

// ---- empty state --------------------------------------------------------------

@Composable
private fun EmptyState(modifier: Modifier, onImport: () -> Unit) {
    Column(
        modifier.fillMaxSize().padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        AppIcon(112.dp)
        Spacer(Modifier.height(28.dp))
        Text("No passkeys yet", style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(12.dp))
        Text(
            "Import the passkeys from a Bitwarden export (unencrypted .json). They are encrypted with the Android Keystore and never leave this phone.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(28.dp))
        FilledTonalButton(onClick = onImport, contentPadding = PaddingValues(horizontal = 24.dp, vertical = 14.dp)) {
            Icon(AppIcons.FileDownload, null, Modifier.size(ButtonDefaults.IconSize))
            Spacer(Modifier.width(ButtonDefaults.IconSpacing))
            Text("Import passkeys")
        }
        Spacer(Modifier.height(96.dp)) // keep clear of the FAB
    }
}

/** The launcher icon, drawn from its two vector layers. */
@Composable
private fun AppIcon(size: Dp) {
    Box(Modifier.size(size).clip(RoundedCornerShape(size * 0.28f))) {
        // adaptive icon layers are 108dp of which launchers show the middle 72dp: zoom to match
        val zoom = Modifier.fillMaxSize().graphicsLayer(scaleX = 1.5f, scaleY = 1.5f)
        Image(painterResource(R.drawable.ic_launcher_background), null, zoom)
        Image(painterResource(R.drawable.ic_launcher_foreground), null, zoom)
    }
}

// ---- details sheet ---------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PasskeySheet(pk: Passkey, onDismiss: () -> Unit, onCopied: () -> Unit, onDelete: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.navigationBarsPadding().padding(bottom = 16.dp)) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                SiteAvatar(pk, 64.dp)
                Spacer(Modifier.height(12.dp))
                Text(pk.label, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                Text(
                    pk.rpName.ifBlank { pk.rpId },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(16.dp))
            if (pk.userDisplayName.isNotBlank()) DetailRow(Icons.Rounded.Person, "Name", pk.userDisplayName)
            DetailRow(AppIcons.Language, "Website", pk.rpId)
            DetailRow(
                AppIcons.Key, "Credential ID", shortId(pk.credentialId), mono = true,
                trailing = {
                    IconButton(onClick = { clipboard.setText(AnnotatedString(pk.credentialId)); onCopied() }) {
                        Icon(AppIcons.ContentCopy, "Copy credential ID")
                    }
                },
            )
            if (pk.creationDate.isNotBlank()) DetailRow(AppIcons.Event, "Created", pk.creationDate.take(10))
            DetailRow(AppIcons.Tag, "Signature counter", pk.counter.toString())
            DetailRow(Icons.Rounded.Lock, "Key", "${pk.keyAlgorithm} ${pk.keyCurve}, encrypted on this phone")
            Spacer(Modifier.height(16.dp))
            OutlinedButton(
                onClick = onDelete,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) {
                Icon(Icons.Rounded.Delete, null, Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text("Delete passkey")
            }
        }
    }
}

@Composable
private fun DetailRow(
    icon: ImageVector,
    label: String,
    value: String,
    mono: Boolean = false,
    trailing: (@Composable () -> Unit)? = null,
) {
    ListItem(
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        leadingContent = { Icon(icon, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) },
        overlineContent = { Text(label) },
        headlineContent = {
            Text(value, fontFamily = if (mono) FontFamily.Monospace else null, maxLines = 2, overflow = TextOverflow.Ellipsis)
        },
        trailingContent = trailing,
        modifier = Modifier.padding(horizontal = 8.dp),
    )
}

private fun shortId(id: String): String = if (id.length <= 20) id else id.take(10) + "…" + id.takeLast(6)

// ---- dialogs ------------------------------------------------------------------------

@Composable
private fun UpdateDialog(u: UpdateUi, current: String, onDismiss: () -> Unit, onInstall: (UpdateChecker.Release) -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(AppIcons.SystemUpdate, null) },
        title = {
            Text(
                when (u) {
                    UpdateUi.Checking -> "Checking for updates"
                    is UpdateUi.Downloading -> "Downloading update"
                    is UpdateUi.Result -> when (u.status) {
                        is UpdateChecker.Status.UpToDate -> "You're up to date"
                        is UpdateChecker.Status.Available -> "Update available"
                        is UpdateChecker.Status.Error -> "Couldn't check for updates"
                    }
                },
            )
        },
        text = {
            when (u) {
                UpdateUi.Checking -> Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                is UpdateUi.Downloading -> Column {
                    Text(u.release.label)
                    Spacer(Modifier.height(16.dp))
                    LinearProgressIndicator(progress = { u.percent / 100f }, modifier = Modifier.fillMaxWidth())
                }
                is UpdateUi.Result -> Text(
                    when (val s = u.status) {
                        is UpdateChecker.Status.UpToDate -> "You have the newest version, $current."
                        is UpdateChecker.Status.Available -> "${s.release.label} is available. You have $current."
                        is UpdateChecker.Status.Error -> s.message
                    },
                )
            }
        },
        confirmButton = {
            val s = (u as? UpdateUi.Result)?.status
            when {
                s is UpdateChecker.Status.Available -> TextButton(onClick = { onInstall(s.release) }) { Text("Install") }
                u is UpdateUi.Result -> TextButton(onClick = onDismiss) { Text("OK") }
                else -> {}
            }
        },
        dismissButton = {
            if ((u as? UpdateUi.Result)?.status is UpdateChecker.Status.Available || u is UpdateUi.Checking) {
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}

@Composable
private fun AboutDialog(version: String, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { AppIcon(56.dp) },
        title = { Text("PassKeyChain") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                Text(version, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(12.dp))
                Text(
                    "Keeps your passkeys on your own phone, encrypted with the Android Keystore.\n\n" +
                        "Free software under the GNU GPL v3.\ngithub.com/rsnel/passkeychain",
                    textAlign = TextAlign.Center,
                )
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("OK") } },
    )
}
