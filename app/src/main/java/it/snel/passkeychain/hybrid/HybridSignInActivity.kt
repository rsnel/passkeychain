package it.snel.passkeychain.hybrid

import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import it.snel.passkeychain.hybrid.CtapAuthenticator.Decision
import it.snel.passkeychain.hybrid.CtapAuthenticator.GetAssertionRequest
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.store.PasskeyStore
import it.snel.passkeychain.store.UserUnlock
import it.snel.passkeychain.ui.AppIcons
import it.snel.passkeychain.ui.SiteAvatar
import it.snel.passkeychain.ui.theme.PassKeyChainTheme
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Signs in on a computer from its QR code. The tunnel runs on a worker thread;
 * when the browser's request arrives, this screen shows the passkeys that fit
 * it (a choice when there is more than one), asks for the screen lock, and only
 * then lets the worker sign.
 */
class HybridSignInActivity : FragmentActivity() {
    private val TAG = "HybridSignInActivity"
    private lateinit var bleAdvertiser: AndroidBleAdvertiser

    private sealed interface Ui {
        data object Connecting : Ui
        class Choose(val request: GetAssertionRequest, val candidates: List<Passkey>) : Ui
        class Unlocking(val passkey: Passkey) : Ui
        class Signing(val passkey: Passkey) : Ui
        class Done(val passkey: Passkey) : Ui
        class Failed(val title: String, val message: String) : Ui
    }

    private var ui by mutableStateOf<Ui>(Ui.Connecting)

    /** The worker thread waits on this for the user's decision. */
    @Volatile private var pending: CompletableFuture<Decision>? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent { PassKeyChainTheme { Screen(ui, onPick = ::unlockAndSign, onClose = ::cancelAndClose) } }

        val qr = intent.getStringExtra("qr_text")?.let { runCatching { FidoQr.parse(it) }.getOrNull() }
        if (qr == null) {
            ui = Ui.Failed("Not a sign-in QR code", "This QR code is not a passkey sign-in request.")
            return
        }
        if (PasskeyStore(applicationContext).load().isEmpty()) {
            ui = Ui.Failed("No passkeys", "Import your passkeys from Bitwarden first.")
            return
        }

        bleAdvertiser = AndroidBleAdvertiser(this)
        val transport = HybridTransport(bleAdvertiser, NoiseTunnelClient())
        Thread({
            try {
                transport.authenticate(qr) { request -> choose(request) }
                Log.d(TAG, "authenticate() returned")
                runOnUiThread { (ui as? Ui.Signing)?.let { ui = Ui.Done(it.passkey) } }
            } catch (e: Exception) {
                Log.e(TAG, "authenticate() failed", e)
                runOnUiThread {
                    // a refusal or "no passkey" already shows its own message
                    if (ui !is Ui.Failed) ui = Ui.Failed("Sign-in failed", e.message ?: e.javaClass.simpleName)
                }
            }
        }, "hybrid-sign-in").apply { isDaemon = true }.start()
    }

    /** Runs on the worker thread when the browser's request arrives; blocks until the user decided. */
    private fun choose(request: GetAssertionRequest): Decision {
        val future = CompletableFuture<Decision>()
        pending = future
        runOnUiThread { onRequest(request, future) }
        return try {
            future.get(3, TimeUnit.MINUTES)
        } catch (e: TimeoutException) {
            runOnUiThread { ui = Ui.Failed("Timed out", "No passkey was chosen in time.") }
            Decision.Denied
        } finally {
            pending = null
        }
    }

    private fun onRequest(request: GetAssertionRequest, future: CompletableFuture<Decision>) {
        val candidates = PasskeyStore(applicationContext).load().filter { request.accepts(it) }
        Log.d(TAG, "request for ${request.rpId}, allowList=${request.allowList.size}, candidates=${candidates.size}")
        when (candidates.size) {
            0 -> {
                ui = Ui.Failed(
                    "No passkey for ${request.rpId}",
                    "None of your passkeys can sign in to this website. Import it from Bitwarden first.",
                )
                future.complete(Decision.NoCredentials)
            }
            1 -> unlockAndSign(candidates.single())
            else -> ui = Ui.Choose(request, candidates)
        }
    }

    /** Asks for the screen lock (fingerprint, face or PIN/pattern/password); only then may the worker sign. */
    private fun unlockAndSign(pk: Passkey) {
        val future = pending ?: return
        val back = ui as? Ui.Choose
        ui = Ui.Unlocking(pk)
        UserUnlock.prompt(
            this,
            title = "Sign in to ${pk.rpName.ifBlank { pk.rpId }}",
            subtitle = pk.label,
            description = "Confirm it's you to sign in on your computer",
            onSuccess = {
                ui = Ui.Signing(pk)
                future.complete(Decision.Sign(pk))
            },
            onError = { cancelled, message ->
                if (cancelled && back != null) {
                    ui = back // back to the choice; the browser keeps waiting
                } else {
                    ui = if (!UserUnlock.available(this)) Ui.Failed("Set a screen lock first", UserUnlock.NO_SCREEN_LOCK)
                    else Ui.Failed(if (cancelled) "Cancelled" else "Could not unlock", message)
                    future.complete(Decision.Denied)
                }
            },
        )
    }

    private fun cancelAndClose() {
        pending?.complete(Decision.Denied)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        pending?.complete(Decision.Denied)
        if (::bleAdvertiser.isInitialized) bleAdvertiser.stop()
    }

    // ---- UI -------------------------------------------------------------------

    @Composable
    private fun Screen(ui: Ui, onPick: (Passkey) -> Unit, onClose: () -> Unit) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp)) {
                Box(Modifier.fillMaxWidth()) {
                    TextButton(onClick = onClose, modifier = Modifier.align(Alignment.TopStart)) {
                        Icon(Icons.Rounded.Close, null, Modifier.size(18.dp))
                        Text(if (ui is Ui.Done || ui is Ui.Failed) "  Close" else "  Cancel")
                    }
                }
                when (ui) {
                    Ui.Connecting -> Status(
                        title = "Waiting for your computer",
                        text = "Keep this phone near the computer. Bluetooth tells the computer that you are nearby; the sign-in itself goes through an encrypted connection.",
                        busy = true,
                    )
                    is Ui.Choose -> Choose(ui, onPick)
                    is Ui.Unlocking -> Status(Icons.Rounded.Lock, "Confirm it's you", "Unlock to sign in to ${site(ui.passkey)} as ${ui.passkey.label}.")
                    is Ui.Signing -> Status(title = "Signing in", text = "Sending the signature to your computer…", busy = true)
                    is Ui.Done -> Status(Icons.Rounded.Check, "Signed in on your computer", "${ui.passkey.label} at ${site(ui.passkey)}.", good = true) {
                        FilledTonalButton(onClick = onClose) { Text("Done") }
                    }
                    is Ui.Failed -> Status(Icons.Rounded.Close, ui.title, ui.message, bad = true) {
                        FilledTonalButton(onClick = onClose) { Text("Close") }
                    }
                }
            }
        }
    }

    @Composable
    private fun Status(
        icon: ImageVector? = null,
        title: String,
        text: String,
        busy: Boolean = false,
        good: Boolean = false,
        bad: Boolean = false,
        action: (@Composable () -> Unit)? = null,
    ) {
        Column(
            Modifier.fillMaxSize().padding(bottom = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            val scheme = MaterialTheme.colorScheme
            val (bg, fg) = when {
                good -> Color(0xFF2BB59A) to Color.White
                bad -> scheme.errorContainer to scheme.onErrorContainer
                else -> scheme.primaryContainer to scheme.onPrimaryContainer
            }
            Box(Modifier.size(96.dp).clip(CircleShape).background(bg), contentAlignment = Alignment.Center) {
                if (busy) CircularProgressIndicator(Modifier.size(48.dp), color = fg, strokeWidth = 4.dp)
                else Icon(icon ?: AppIcons.QrCodeScanner, null, Modifier.size(48.dp), tint = fg)
            }
            Spacer(Modifier.height(28.dp))
            Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
            Spacer(Modifier.height(12.dp))
            Text(text, style = MaterialTheme.typography.bodyLarge, color = scheme.onSurfaceVariant, textAlign = TextAlign.Center)
            if (action != null) { Spacer(Modifier.height(28.dp)); action() }
        }
    }

    @Composable
    private fun Choose(ui: Ui.Choose, onPick: (Passkey) -> Unit) {
        val first = ui.candidates.first()
        Column(Modifier.fillMaxSize()) {
            Spacer(Modifier.height(16.dp))
            Text("Choose a passkey", style = MaterialTheme.typography.headlineSmall)
            Text(
                "to sign in to ${site(first)} on your computer",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(20.dp))
            LazyColumn(verticalArrangement = Arrangement.spacedBy(2.dp), contentPadding = PaddingValues(bottom = 24.dp)) {
                itemsIndexed(ui.candidates) { i, pk ->
                    val big = 20.dp; val small = 4.dp
                    val shape = RoundedCornerShape(
                        topStart = if (i == 0) big else small, topEnd = if (i == 0) big else small,
                        bottomStart = if (i == ui.candidates.lastIndex) big else small,
                        bottomEnd = if (i == ui.candidates.lastIndex) big else small,
                    )
                    Surface(shape = shape, color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.fillMaxWidth()) {
                        ListItem(
                            modifier = Modifier.clickable { onPick(pk) },
                            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                            leadingContent = { SiteAvatar(pk) },
                            headlineContent = { Text(pk.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            supportingContent = {
                                Text(pk.userDisplayName.takeIf { it.isNotBlank() && it != pk.label } ?: pk.rpId, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            },
                            trailingContent = { Icon(AppIcons.ChevronRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) },
                        )
                    }
                }
            }
        }
    }

    private fun site(pk: Passkey) = pk.rpName.ifBlank { pk.rpId }
}
