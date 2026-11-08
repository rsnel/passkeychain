package it.snel.passkeychain.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import it.snel.passkeychain.io.Bitwarden
import it.snel.passkeychain.io.OkHttpVault
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.io.VaultSync
import it.snel.passkeychain.store.VaultSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Read-only sync from a Bitwarden-compatible server: server address, email and
 * master password, and a code when the server asks for a second factor. On
 * success [onSynced] gets the passkeys as a Bitwarden export and the server's
 * host name; nothing is changed on the server.
 */
@Composable
fun VaultSyncDialog(
    settings: VaultSettings,
    onDismiss: () -> Unit,
    onSynced: (exportJson: String, host: String, skipped: Int) -> Unit,
    /** Export mode: these passkeys go to the vault, as far as it lacks them. */
    toVault: List<Passkey>? = null,
    onExported: (added: List<Passkey>, failed: List<String>, host: String) -> Unit = { _, _, _ -> },
) {
    val exporting = toVault != null
    // export: after checking the vault, what would be added (and the open session to do it)
    var plan by remember { mutableStateOf<ExportPlan?>(null) }
    var server by remember { mutableStateOf(settings.server) }
    var email by remember { mutableStateOf(settings.email) }
    var password by remember { mutableStateOf("") }
    var providers by remember { mutableStateOf<List<Int>>(emptyList()) } // asked for a second factor
    var provider by remember { mutableStateOf(-1) }
    var code by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var info by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun sync() {
        error = null; info = null
        scope.launch {
            busy = "Unlocking and fetching the vault…"
            try {
                val vault = withContext(Dispatchers.IO) { VaultSync(server, OkHttpVault(), settings.deviceId) }
                val token = settings.refreshToken(vault.base, email)
                val second = if (provider >= 0 && code.isNotBlank()) VaultSync.TwoFactor(provider, code) else null
                val session = withContext(Dispatchers.Default) { vault.open(email, password, token, second) }
                withContext(Dispatchers.IO) { settings.save(vault.base, email, session.refreshToken) }
                password = ""
                val r = withContext(Dispatchers.Default) { vault.passkeys(session) }
                val host = java.net.URI(vault.base).host
                if (toVault == null) onSynced(r.exportJson, host, r.skipped.size)
                else {
                    val have = Bitwarden.parse(r.exportJson).imported.map { it.credentialId }.toSet()
                    val missing = toVault.filter { it.credentialId !in have }
                    plan = ExportPlan(vault, session, host, missing, toVault.size - missing.size)
                }
            } catch (e: VaultSync.TwoFactorRequired) {
                val usable = e.providers.filter { it == VaultSync.PROVIDER_AUTHENTICATOR || it == VaultSync.PROVIDER_EMAIL }
                if (usable.isEmpty()) {
                    error = "The server asks for a second factor this app can't do (" +
                        e.providers.joinToString { VaultSync.providerName(it) } + "). Use an authenticator app or email."
                } else {
                    providers = usable
                    provider = if (VaultSync.PROVIDER_AUTHENTICATOR in usable) VaultSync.PROVIDER_AUTHENTICATOR else VaultSync.PROVIDER_EMAIL
                    code = ""
                    if (provider == VaultSync.PROVIDER_EMAIL) {
                        busy = "Sending a code…"
                        sendEmail(server, email, password, settings) { info = it; error = null }.invoke()
                    }
                }
            } catch (e: VaultSync.WrongPassword) {
                error = e.message
            } catch (e: VaultSync.Failure) {
                error = e.message
            } catch (e: Exception) {
                error = "Sync failed: ${e.message ?: e.javaClass.simpleName}"
            } finally {
                busy = null
            }
        }
    }

    plan?.let { p ->
        AlertDialog(
            onDismissRequest = { if (busy == null) onDismiss() },
            title = { Text(if (p.missing.isEmpty()) "Nothing to add" else "Add to ${p.host}?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        when {
                            p.missing.isEmpty() -> "All ${p.already} passkeys are already in the vault."
                            else -> "${count(p.missing.size)} not in the vault yet will be added as new items" +
                                (if (p.already > 0) "; ${p.already} already there stay as they are." else ".") +
                                " Nothing in the vault is changed or deleted."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    p.missing.take(8).forEach { pk ->
                        Text("· ${pk.rpId}" + (if (pk.userName.isNotBlank()) " — ${pk.userName}" else ""), style = MaterialTheme.typography.bodySmall)
                    }
                    if (p.missing.size > 8) Text("· and ${p.missing.size - 8} more", style = MaterialTheme.typography.bodySmall)
                    busy?.let {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(10.dp))
                            Text(it, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error) }
                }
            },
            confirmButton = {
                if (p.missing.isNotEmpty()) TextButton(enabled = busy == null, onClick = {
                    scope.launch {
                        busy = "Adding…"; error = null
                        try {
                            val up = withContext(Dispatchers.IO) { p.vault.upload(p.session, p.missing) }
                            onExported(up.added, up.failed, p.host)
                        } catch (e: Exception) {
                            error = e.message ?: "Adding failed."
                        } finally {
                            busy = null
                        }
                    }
                }) { Text("Add ${p.missing.size}") }
            },
            dismissButton = { TextButton(enabled = busy == null, onClick = onDismiss) { Text(if (p.missing.isEmpty()) "Close" else "Cancel") } },
        )
        return
    }

    AlertDialog(
        onDismissRequest = { if (busy == null) onDismiss() },
        title = { Text(if (exporting) "Export to a server" else "Sync from a server") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    if (exporting) "Adds your passkeys to your Bitwarden-compatible server, such as Vaultwarden, " +
                        "as far as they aren't there yet. First the app checks the vault and shows what it would add. " +
                        "Your master password is not stored."
                    else "Fetches the passkeys from your Bitwarden-compatible server, such as Vaultwarden. " +
                        "Read-only: nothing changes on the server. Only passkeys are decrypted; " +
                        "your master password is not stored.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    server, { server = it.trim() }, label = { Text("Server address") },
                    placeholder = { Text("https://vault.example.com") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Next),
                    enabled = busy == null, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    email, { email = it }, label = { Text("Email") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
                    enabled = busy == null, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    password, { password = it }, label = { Text("Master password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                    enabled = busy == null, modifier = Modifier.fillMaxWidth(),
                )
                if (providers.isNotEmpty()) {
                    Text(
                        if (provider == VaultSync.PROVIDER_EMAIL) "Enter the code the server emailed you."
                        else "Enter the code from your authenticator app.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedTextField(
                        code, { code = it }, label = { Text("Code") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
                        enabled = busy == null, modifier = Modifier.fillMaxWidth(),
                    )
                    if (providers.size > 1) TextButton(
                        enabled = busy == null,
                        onClick = {
                            provider = if (provider == VaultSync.PROVIDER_EMAIL) VaultSync.PROVIDER_AUTHENTICATOR else VaultSync.PROVIDER_EMAIL
                            code = ""
                            if (provider == VaultSync.PROVIDER_EMAIL) scope.launch {
                                busy = "Sending a code…"
                                sendEmail(server, email, password, settings) { info = it; error = null }.invoke()
                                busy = null
                            }
                        },
                    ) { Text(if (provider == VaultSync.PROVIDER_EMAIL) "Use the authenticator app instead" else "Email me a code instead") }
                }
                busy?.let {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                        Text(it, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                info?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error) }
                if (settings.hasToken() && busy == null) TextButton(onClick = {
                    settings.forget(); server = ""; email = ""; info = "Server and sign-in forgotten."
                }) { Text("Forget this server") }
            }
        },
        confirmButton = {
            TextButton(
                enabled = busy == null && server.isNotBlank() && email.isNotBlank() && password.isNotEmpty() &&
                    (providers.isEmpty() || code.isNotBlank()),
                onClick = ::sync,
            ) { Text(if (exporting) "Check" else "Sync") }
        },
        dismissButton = { TextButton(enabled = busy == null, onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Asks the server to email a login code; reports the outcome through [report]. */
private fun sendEmail(server: String, email: String, password: String, settings: VaultSettings, report: (String) -> Unit): suspend () -> Unit = {
    val message = try {
        withContext(Dispatchers.Default) { VaultSync(server, OkHttpVault(), settings.deviceId).sendEmailCode(email, password) }
        "A code is on its way to $email."
    } catch (e: Exception) {
        e.message ?: "Could not send a code."
    }
    report(message)
}

private class ExportPlan(
    val vault: VaultSync,
    val session: VaultSync.Session,
    val host: String,
    val missing: List<Passkey>,
    val already: Int,
)

private fun count(n: Int) = if (n == 1) "1 passkey" else "$n passkeys"
