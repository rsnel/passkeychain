package it.snel.passkeychain.ui

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.withResumed
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.Lifecycle
import androidx.compose.runtime.DisposableEffect
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
import it.snel.passkeychain.store.SignInHistory
import it.snel.passkeychain.model.HistoryEntry
import androidx.compose.ui.semantics.semantics
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Check
import androidx.compose.foundation.layout.heightIn
import androidx.compose.runtime.produceState
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
import it.snel.passkeychain.hybrid.HybridSignInActivity
import it.snel.passkeychain.io.Bitwarden
import it.snel.passkeychain.io.Cxf
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import it.snel.passkeychain.BuildConfig
import it.snel.passkeychain.io.BitwardenEncrypted
import it.snel.passkeychain.util.Dbg
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
    /** Android must first allow this app to install apps ("Install unknown apps"). */
    data class NeedsPermission(val release: UpdateChecker.Release) : UpdateUi
    /** Downloaded and checked; the installer opens as soon as the app is in the foreground. */
    data class Ready(val release: UpdateChecker.Release, val apk: java.io.File) : UpdateUi
}

/** An encrypted backup that is waiting for its password. */
private data class PendingImport(val text: String, val error: String? = null)

/** Imports an unencrypted Bitwarden JSON export or a Credential Exchange (CXF) document; returns the message to show. */
private fun importJson(store: PasskeyStore, text: String): String {
    val res = if (Cxf.hasPasskeys(text)) Cxf.parse(text) else Bitwarden.parse(text)
    res.imported.forEach { store.upsert(it) }
    val n = res.imported.size
    return (if (n == 1) "Imported 1 passkey" else "Imported $n passkeys") +
        if (res.skipped.isNotEmpty()) ", skipped ${res.skipped.size}" else ""
}

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
    var about by remember { mutableStateOf(false) }
    var exportChoice by remember { mutableStateOf(false) }
    var exportPassword by remember { mutableStateOf<String?>(null) } // null: unencrypted
    var pendingImport by remember { mutableStateOf<PendingImport?>(null) }
    var busy by remember { mutableStateOf<String?>(null) }
    var debugLogging by remember { mutableStateOf(Dbg.enabled) }
    val history = remember { SignInHistory(ctx) }
    var historyShown by remember { mutableStateOf<List<HistoryEntry>?>(null) } // null: closed

    // load the list, and again whenever the app comes back to the front: a
    // passkey may have been created on the sign-in screen meanwhile
    DisposableEffect(activity) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) scope.launch {
                passkeys = withContext(Dispatchers.IO) { store.load() }
                loaded = true
            }
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                runCatching {
                    val text = ctx.contentResolver.openInputStream(uri)!!.use { it.readBytes().toString(Charsets.UTF_8) }
                    when {
                        BitwardenEncrypted.isPasswordProtected(text) -> { pendingImport = PendingImport(text); null }
                        BitwardenEncrypted.isEncrypted(text) ->
                            "This is an \"account restricted\" Bitwarden export, which only Bitwarden can read. " +
                                "Export again as .json (Encrypted) with export type \"Password protected\"."
                        else -> importJson(store, text).also { passkeys = store.load() }
                    }
                }.getOrElse { "Import failed: ${it.message}" }
            }
            msg?.let { snackbar.showSnackbar(it) }
        }
    }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri == null) { exportPassword = null; return@rememberLauncherForActivityResult }
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                runCatching {
                    val all = store.load()
                    val password = exportPassword
                    val content = if (password != null) {
                        busy = "Encrypting the backup…"
                        withContext(Dispatchers.Default) { BitwardenEncrypted.encrypt(Bitwarden.export(all), password) }
                    } else Bitwarden.export(all)
                    ctx.contentResolver.openOutputStream(uri)!!.use { it.write(content.toByteArray()) }
                    // passkeys created on this phone now have a copy elsewhere (backup state)
                    if (all.any { !it.backedUp }) store.save(all.map { it.copy(backedUp = true) })
                    (if (all.size == 1) "Exported 1 passkey" else "Exported ${all.size} passkeys") +
                        if (password != null) ", encrypted" else ""
                }.getOrElse { "Export failed: ${it.message}" }
            }
            busy = null
            exportPassword = null
            snackbar.showSnackbar(msg)
        }
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
                                    description = "An export gives access to all your passkeys.",
                                    onSuccess = { exportChoice = true },
                                    onError = { cancelled, message -> if (!cancelled) scope.launch { snackbar.showSnackbar(message) } },
                                )
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Sign-in history") },
                            leadingIcon = { Icon(AppIcons.History, null) },
                            onClick = {
                                menuOpen = false
                                scope.launch { historyShown = withContext(Dispatchers.IO) { history.load() } }
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
                        if (BuildConfig.DEBUG) {
                            DropdownMenuItem(
                                text = { Text("Debug logging") },
                                leadingIcon = { Icon(Icons.Rounded.Info, null) },
                                trailingIcon = { Checkbox(checked = debugLogging, onCheckedChange = null) },
                                onClick = {
                                    debugLogging = !debugLogging
                                    Dbg.setEnabled(ctx, debugLogging)
                                    scope.launch { snackbar.showSnackbar(if (debugLogging) "Debug logging on (may log key material)" else "Debug logging off") }
                                },
                            )
                        }
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
                onClick = { ctx.startActivity(Intent(ctx, HybridSignInActivity::class.java)) },
            )
        },
    ) { padding ->
        when {
            !loaded -> Box(Modifier.fillMaxSize().padding(padding))
            passkeys.isEmpty() -> EmptyState(Modifier.padding(padding), onImport = openImport)
            else -> PasskeyList(passkeys, listState, padding, onClick = { selected = it })
        }
    }

    historyShown?.let { entries ->
        HistorySheet(
            entries,
            onDismiss = { historyShown = null },
            onClear = {
                scope.launch {
                    withContext(Dispatchers.IO) { history.clear() }
                    historyShown = emptyList()
                }
            },
        )
    }

    selected?.let { pk ->
        val lastUsed by produceState<Long?>(null, pk) {
            value = withContext(Dispatchers.IO) { HistoryEntry.lastUsed(history.load(), pk.credentialId, pk.rpId) }
        }
        PasskeySheet(
            pk,
            lastUsed = lastUsed,
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

    fun startDownload(rel: UpdateChecker.Release) {
        update = UpdateUi.Downloading(rel, 0)
        scope.launch {
            runCatching { updater.download(rel) { p -> scope.launch { if (update is UpdateUi.Downloading) update = UpdateUi.Downloading(rel, p) } } }
                .onSuccess { apk -> update = UpdateUi.Ready(rel, apk) }
                .onFailure {
                    update = null
                    snackbar.showSnackbar("Update failed: ${it.message}")
                }
        }
    }
    val installPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val u = update as? UpdateUi.NeedsPermission ?: return@rememberLauncherForActivityResult
        if (updater.canInstall()) startDownload(u.release)
        else {
            update = null
            scope.launch { snackbar.showSnackbar("Not updated: PassKeyChain may not install apps (\"Install unknown apps\").") }
        }
    }
    // Open the installer once the download is ready, but only while the app is in
    // the foreground: Android silently ignores an installer started from the
    // background (for instance when the user switched apps during the download).
    (update as? UpdateUi.Ready)?.let { ready ->
        LaunchedEffect(ready) {
            activity.lifecycle.withResumed {
                runCatching { updater.install(ready.apk) }
                    .onFailure { scope.launch { snackbar.showSnackbar("Could not open the installer: ${it.message}") } }
            }
        }
    }

    update?.let { u ->
        UpdateDialog(
            u, current = updater.currentLabel,
            onDismiss = { if (u !is UpdateUi.Downloading) update = null },
            onInstall = { rel ->
                when {
                    u is UpdateUi.Ready -> runCatching { updater.install(u.apk) }
                        .onFailure { scope.launch { snackbar.showSnackbar("Could not open the installer: ${it.message}") } }
                    updater.canInstall() -> startDownload(rel)
                    u is UpdateUi.NeedsPermission -> installPermission.launch(updater.installPermissionIntent())
                    else -> update = UpdateUi.NeedsPermission(rel)
                }
            },
        )
    }

    if (exportChoice) ExportDialog(
        onDismiss = { exportChoice = false },
        onExport = { password ->
            exportChoice = false
            exportPassword = password
            exportLauncher.launch(if (password != null) "passkeychain-bitwarden-encrypted.json" else "passkeychain-bitwarden.json")
        },
    )

    pendingImport?.let { p ->
        ImportPasswordDialog(
            p,
            onDismiss = { pendingImport = null },
            onDecrypt = { password ->
                pendingImport = p.copy(error = null)
                busy = "Decrypting the backup…"
                scope.launch {
                    val result = withContext(Dispatchers.Default) {
                        runCatching { BitwardenEncrypted.decrypt(p.text, password) }
                    }
                    busy = null
                    result.fold(
                        onSuccess = { inner ->
                            pendingImport = null
                            val msg = withContext(Dispatchers.IO) {
                                runCatching { importJson(store, inner).also { passkeys = store.load() } }
                                    .getOrElse { "Import failed: ${it.message}" }
                            }
                            snackbar.showSnackbar(msg)
                        },
                        onFailure = { e ->
                            if (e is BitwardenEncrypted.WrongPassword) pendingImport = p.copy(error = "Wrong password")
                            else { pendingImport = null; snackbar.showSnackbar("Import failed: ${e.message}") }
                        },
                    )
                }
            },
        )
    }

    busy?.let { BusyDialog(it) }

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

// ---- sign-in history -------------------------------------------------------------

private fun formatTime(millis: Long): String =
    java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT).format(java.util.Date(millis))

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HistorySheet(entries: List<HistoryEntry>, onDismiss: () -> Unit, onClear: () -> Unit) {
    val green = Color(0xFF1E9E5A)
    val red = Color(0xFFC62828)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.navigationBarsPadding()) {
            Row(Modifier.fillMaxWidth().padding(start = 24.dp, end = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Sign-in history", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                if (entries.isNotEmpty()) TextButton(onClick = onClear) { Text("Clear") }
            }
            Text(
                "The last ${HistoryEntry.MAX} sign-ins with PassKeyChain, kept encrypted on this phone.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 24.dp),
            )
            Spacer(Modifier.height(8.dp))
            if (entries.isEmpty()) {
                Text(
                    "No sign-ins yet.",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(24.dp),
                )
            } else LazyColumn(Modifier.fillMaxWidth().heightIn(max = 560.dp)) {
                items(entries, key = { it.time.toString() + it.rpId + it.outcome }) { e ->
                    val ok = e.succeeded
                    val what = when (e.outcome) {
                        HistoryEntry.Outcome.SignedIn -> "Signed in"
                        HistoryEntry.Outcome.Created -> "Passkey created"
                        HistoryEntry.Outcome.Denied -> "Cancelled"
                        HistoryEntry.Outcome.Failed -> "Failed"
                    }
                    val where = if (e.via == HistoryEntry.Via.Computer) "on a computer" else "on this phone"
                    ListItem(
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        leadingContent = {
                            Box(
                                Modifier.size(28.dp).clip(CircleShape).background(if (ok) green else red),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(if (ok) Icons.Rounded.Check else Icons.Rounded.Close, null, Modifier.size(18.dp), tint = Color.White)
                            }
                        },
                        headlineContent = { Text(e.rpId.ifBlank { "Unknown site" }, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        supportingContent = {
                            Column {
                                Text(listOf(e.account, "$what $where").filter { it.isNotBlank() }.joinToString(" · "))
                                Text(formatTime(e.time), color = MaterialTheme.colorScheme.onSurfaceVariant)
                                if (e.detail.isNotBlank()) Text(e.detail, color = red)
                            }
                        },
                        modifier = Modifier.padding(horizontal = 8.dp).semantics(mergeDescendants = true) {},
                    )
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

// ---- details sheet ---------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PasskeySheet(pk: Passkey, lastUsed: Long?, onDismiss: () -> Unit, onCopied: () -> Unit, onDelete: () -> Unit) {
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
            DetailRow(AppIcons.History, "Last used", lastUsed?.let(::formatTime) ?: "Not with PassKeyChain yet")
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
                    is UpdateUi.NeedsPermission -> "Allow updates"
                    is UpdateUi.Ready -> "Ready to install"
                    is UpdateUi.Result -> when (u.status) {
                        is UpdateChecker.Status.UpToDate -> "You're up to date"
                        is UpdateChecker.Status.Building -> "Update on its way"
                        is UpdateChecker.Status.Available -> "Update available"
                        is UpdateChecker.Status.Error -> "Couldn't check for updates"
                    }
                },
            )
        },
        text = {
            when (u) {
                UpdateUi.Checking -> Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                is UpdateUi.NeedsPermission -> Text(
                    "To install ${u.release.label}, Android needs your permission once: switch on " +
                        "\"Allow from this source\" for PassKeyChain, then come back here.",
                )
                is UpdateUi.Ready -> Text(
                    "${u.release.label} has been downloaded. If the installer did not open, tap Install.",
                )
                is UpdateUi.Downloading -> Column {
                    Text(u.release.label)
                    Spacer(Modifier.height(16.dp))
                    LinearProgressIndicator(progress = { u.percent / 100f }, modifier = Modifier.fillMaxWidth())
                }
                is UpdateUi.Result -> Text(
                    when (val s = u.status) {
                        is UpdateChecker.Status.UpToDate -> "You have the newest version, $current."
                        is UpdateChecker.Status.Building ->
                            "Build ${s.build} is still being built on GitHub. Check again in a few minutes. You have $current."
                        is UpdateChecker.Status.Available -> "${s.release.label} is available. You have $current."
                        is UpdateChecker.Status.Error -> s.message
                    },
                )
            }
        },
        confirmButton = {
            val s = (u as? UpdateUi.Result)?.status
            when {
                u is UpdateUi.NeedsPermission -> TextButton(onClick = { onInstall(u.release) }) { Text("Open settings") }
                u is UpdateUi.Ready -> TextButton(onClick = { onInstall(u.release) }) { Text("Install") }
                s is UpdateChecker.Status.Available -> TextButton(onClick = { onInstall(s.release) }) { Text("Install") }
                u is UpdateUi.Result -> TextButton(onClick = onDismiss) { Text("OK") }
                else -> {}
            }
        },
        dismissButton = {
            if ((u as? UpdateUi.Result)?.status is UpdateChecker.Status.Available || u is UpdateUi.Checking ||
                u is UpdateUi.NeedsPermission
            ) {
                TextButton(onClick = onDismiss) { Text("Cancel") }
            } else if (u is UpdateUi.Ready) {
                TextButton(onClick = onDismiss) { Text("Later") }
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

@Composable
private fun ExportDialog(onDismiss: () -> Unit, onExport: (password: String?) -> Unit) {
    var encrypted by remember { mutableStateOf(true) }
    var password by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    val problem = when {
        !encrypted -> null
        password.length < 8 -> "At least 8 characters"
        repeat != password -> "The passwords differ"
        else -> null
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(AppIcons.FileUpload, null) },
        title = { Text("Export passkeys") },
        text = {
            Column {
                Text(
                    "In Bitwarden's format, so Bitwarden can import it.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Row(Modifier.fillMaxWidth().clickable { encrypted = true }, verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = encrypted, onClick = { encrypted = true })
                    Text("Encrypted with a password (recommended)")
                }
                Row(Modifier.fillMaxWidth().clickable { encrypted = false }, verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = !encrypted, onClick = { encrypted = false })
                    Text("Unencrypted")
                }
                if (encrypted) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = password, onValueChange = { password = it }, label = { Text("Password") },
                        singleLine = true, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = repeat, onValueChange = { repeat = it }, label = { Text("Repeat password") },
                        singleLine = true, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth(),
                        isError = problem != null && repeat.isNotEmpty(),
                        supportingText = { Text(problem ?: "Bitwarden asks for this password when importing.") },
                    )
                } else {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Anyone who gets the file can use all your passkeys. Delete it as soon as you no longer need it.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(enabled = problem == null, onClick = { onExport(if (encrypted) password else null) }) { Text("Export") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ImportPasswordDialog(p: PendingImport, onDismiss: () -> Unit, onDecrypt: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Rounded.Lock, null) },
        title = { Text("Encrypted backup") },
        text = {
            Column {
                Text("Enter the password this Bitwarden backup was exported with.")
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = password, onValueChange = { password = it }, label = { Text("Password") },
                    singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth(),
                    isError = p.error != null,
                    supportingText = if (p.error != null) { { Text(p.error) } } else null,
                )
            }
        },
        confirmButton = { TextButton(enabled = password.isNotEmpty(), onClick = { onDecrypt(password) }) { Text("Import") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun BusyDialog(text: String) {
    AlertDialog(
        onDismissRequest = {},
        text = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(32.dp))
                Spacer(Modifier.width(20.dp))
                Text(text)
            }
        },
        confirmButton = {},
    )
}
