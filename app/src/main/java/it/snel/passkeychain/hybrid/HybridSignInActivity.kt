package it.snel.passkeychain.hybrid

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.Image
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.layout.ContentScale
import kotlin.math.PI
import kotlin.math.sin
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import it.snel.passkeychain.hybrid.CtapAuthenticator.Decision
import it.snel.passkeychain.hybrid.CtapAuthenticator.GetAssertionRequest
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.store.PasskeyStore
import it.snel.passkeychain.store.UserUnlock
import it.snel.passkeychain.ui.AppIcons
import it.snel.passkeychain.ui.SiteAvatar
import it.snel.passkeychain.ui.theme.PassKeyChainTheme
import it.snel.passkeychain.util.Dbg
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Signs in on a computer from its QR code, on one screen: the camera in the
 * upper half, and in the lower half a live list of the steps (scan, tunnel,
 * Bluetooth, Noise key exchange, signing). When the browser's request
 * arrives, the passkeys that fit it are offered (a choice when there is more
 * than one), the screen lock is asked, and only then does the worker sign.
 */
/** The colours of the stamps, also used for the step list: done, in progress, failed. */
private val StampGreen = Color(0xFF1E9E5A)
private val StampYellow = Color(0xFFF2B705)
private val StampRed = Color(0xFFC62828)

class HybridSignInActivity : FragmentActivity() {
    private val TAG = "HybridSignInActivity"

    // ---- progress list --------------------------------------------------------------

    private enum class Step { Scan, Tunnel, Bluetooth, KeyExchange, Sign }

    private sealed interface State {
        data object Pending : State
        data object Active : State
        data object Done : State
        data class Failed(val message: String) : State
    }

    private val states = mutableStateListOf<State>(State.Active, State.Pending, State.Pending, State.Pending, State.Pending)
    private var tunnelHost by mutableStateOf<String?>(null)
    private var scanHint by mutableStateOf<String?>(null)
    private var signDetail by mutableStateOf<String?>(null)
    private var choice by mutableStateOf<List<Passkey>?>(null)
    /** show "Open settings" (a permission that Android no longer asks for) */
    private var settingsButton by mutableStateOf(false)
    private var scannedQr: FidoQr? = null

    /** The camera picture at the moment the QR was recognized, with the QR's corners in its pixels. */
    private class Frozen(val image: ImageBitmap, val quad: List<Offset>)
    private var frozen by mutableStateOf<Frozen?>(null)

    private fun set(step: Step, state: State) = runOnUiThread { states[step.ordinal] = state }
    private fun done(step: Step, next: Step? = null) = runOnUiThread {
        if (states[step.ordinal] is State.Failed) return@runOnUiThread
        states[step.ordinal] = State.Done
        next?.let { if (states[it.ordinal] == State.Pending) states[it.ordinal] = State.Active }
    }
    private val failed get() = states.any { it is State.Failed }

    /** "Remove animations" (accessibility) or animator duration scale 0 in the developer options */
    private val reduceMotion by lazy {
        android.provider.Settings.Global.getFloat(contentResolver, android.provider.Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f
    }

    // ---- camera ---------------------------------------------------------------------

    private lateinit var previewView: PreviewView
    private val analysisExecutor = Executors.newSingleThreadExecutor()
    private val scanner = BarcodeScanning.getClient()
    private var cameraProvider: ProcessCameraProvider? = null
    @Volatile private var scanned = false

    // ---- exchange -------------------------------------------------------------------

    private var bleAdvertiser: AndroidBleAdvertiser? = null
    @Volatile private var transport: HybridTransport? = null
    /** The worker thread waits on this for the user's decision. */
    @Volatile private var pending: CompletableFuture<Decision>? = null

    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
        if (granted[Manifest.permission.CAMERA] == true || hasPermission(Manifest.permission.CAMERA)) startCamera()
        else {
            settingsButton = true
            set(Step.Scan, State.Failed("PassKeyChain needs the camera to scan the QR code. Allow it in the app's settings."))
        }
    }

    private fun hasPermission(p: String) = ContextCompat.checkSelfPermission(this, p) == PackageManager.PERMISSION_GRANTED

    private val bluetoothPermissions =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            arrayOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
        else emptyArray() // Android 9-11: BLUETOOTH/BLUETOOTH_ADMIN, granted at install

    private val askBluetoothPermission = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        if (bluetoothPermissions.all(::hasPermission)) checkBluetoothAndStart()
        else {
            settingsButton = true
            set(Step.Bluetooth, State.Failed(
                "PassKeyChain needs the \"Nearby devices\" permission to tell your computer that the phone is nearby. " +
                    "Allow it in the app's settings.",
            ))
        }
    }

    private val askBluetoothOn = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (bluetoothAdapter()?.isEnabled == true) checkBluetoothAndStart()
        else set(Step.Bluetooth, State.Failed("Bluetooth is off. It is needed to tell your computer that the phone is nearby."))
    }

    private fun bluetoothAdapter() = (getSystemService(BLUETOOTH_SERVICE) as android.bluetooth.BluetoothManager).adapter

    /** After the scan: "Nearby devices" allowed and Bluetooth on, before anything is opened. */
    private fun checkBluetoothAndStart() {
        val qr = scannedQr ?: return
        val adapter = bluetoothAdapter()
        when {
            !bluetoothPermissions.all(::hasPermission) -> askBluetoothPermission.launch(bluetoothPermissions)
            adapter == null -> set(Step.Bluetooth, State.Failed("This phone has no Bluetooth."))
            !adapter.isEnabled -> askBluetoothOn.launch(android.content.Intent(android.bluetooth.BluetoothAdapter.ACTION_REQUEST_ENABLE))
            else -> start(qr)
        }
    }

    private fun openAppSettings() {
        startActivity(
            android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(android.net.Uri.fromParts("package", packageName, null)),
        )
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        previewView = PreviewView(this).apply { scaleType = PreviewView.ScaleType.FILL_CENTER }
        setContent { PassKeyChainTheme { Screen() } }

        if (PasskeyStore(applicationContext).load().isEmpty()) {
            set(Step.Scan, State.Failed("Import your passkeys from Bitwarden first."))
            return
        }
        // the camera, and on Android 12+ "Nearby devices" for the Bluetooth broadcast
        val wanted = buildList {
            add(Manifest.permission.CAMERA)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.BLUETOOTH_ADVERTISE); add(Manifest.permission.BLUETOOTH_CONNECT)
            }
        }.filterNot(::hasPermission)
        if (wanted.isEmpty()) startCamera() else permissions.launch(wanted.toTypedArray())
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get().also { cameraProvider = it }
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { it.setAnalyzer(analysisExecutor, ::analyze) }
            provider.unbindAll()
            provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(this))
    }

    @androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
    private fun analyze(proxy: ImageProxy) {
        val media = proxy.image
        if (media == null || scanned) { proxy.close(); return }
        val rotation = proxy.imageInfo.rotationDegrees
        val imageW = if (rotation % 180 == 0) proxy.width else proxy.height // ML Kit's coordinates are upright
        val imageH = if (rotation % 180 == 0) proxy.height else proxy.width
        scanner.process(InputImage.fromMediaImage(media, rotation))
            .addOnSuccessListener { codes ->
                val code = codes.firstOrNull { it.format == Barcode.FORMAT_QR_CODE && it.rawValue != null } ?: return@addOnSuccessListener
                val text = code.rawValue!!
                if (scanned) return@addOnSuccessListener
                if (!FidoQr.isFidoQr(text)) { scanHint = "That QR code is not a passkey sign-in. Keep scanning."; return@addOnSuccessListener }
                val qr = runCatching { FidoQr.parse(text) }
                    .onFailure { Dbg.w(TAG, "FIDO QR not readable: ${it.message}") }
                    .getOrNull()
                if (qr == null) { scanHint = "That sign-in QR code could not be read. Hold the phone steady and keep scanning."; return@addOnSuccessListener }
                qr.staleness(System.currentTimeMillis() / 1000)?.let { scanHint = it; return@addOnSuccessListener }
                scanned = true
                scannedQr = qr
                frozen = runCatching { freeze(code, imageW, imageH) }.getOrNull() // before the camera stops
                cameraProvider?.unbindAll()
                if (qr.hint == "mc") {
                    // the site wants to create a passkey; this app only signs in with imported ones
                    set(Step.Scan, State.Failed("This QR code is for creating a new passkey. PassKeyChain can only " +
                        "sign in with passkeys you imported: create the passkey in Bitwarden, then import it."))
                    return@addOnSuccessListener
                }
                done(Step.Scan)
                checkBluetoothAndStart()
            }
            .addOnFailureListener { Dbg.w(TAG, "barcode error", it) }
            .addOnCompleteListener { proxy.close() }
    }

    /**
     * Takes what the preview shows right now, and maps the QR's corners from the
     * analysis image to it. Preview and analysis both use CameraX's default 4:3
     * framing; the preview fills its view (FILL_CENTER): scale, then centre.
     */
    private fun freeze(code: Barcode, imageW: Int, imageH: Int): Frozen? {
        val picture = previewView.bitmap ?: return null
        val vw = picture.width.toFloat(); val vh = picture.height.toFloat()
        val scale = maxOf(vw / imageW, vh / imageH)
        val dx = (vw - imageW * scale) / 2; val dy = (vh - imageH * scale) / 2
        val corners = code.cornerPoints?.map { Offset(it.x * scale + dx, it.y * scale + dy) }
            ?: code.boundingBox?.let { b ->
                listOf(b.left to b.top, b.right to b.top, b.right to b.bottom, b.left to b.bottom)
                    .map { (x, y) -> Offset(x * scale + dx, y * scale + dy) }
            }
            ?: emptyList()
        return Frozen(picture.asImageBitmap(), corners)
    }

    private fun start(qr: FidoQr) {
        set(Step.Tunnel, State.Active)
        val ble = AndroidBleAdvertiser(this).also { bleAdvertiser = it }
        val tunnel = NoiseTunnelClient(onHandshakeDone = {
            ble.stop() // the computer has found the phone: no need to keep broadcasting
            done(Step.KeyExchange, Step.Sign)
        })
        val transport = HybridTransport(ble, tunnel) { p ->
            when (p) {
                is HybridTransport.Progress.TunnelOpening -> runOnUiThread { tunnelHost = p.host }
                HybridTransport.Progress.TunnelOpen -> done(Step.Tunnel, Step.Bluetooth)
                HybridTransport.Progress.Broadcasting -> done(Step.Bluetooth, Step.KeyExchange)
            }
        }
        this.transport = transport
        Thread({
            try {
                val response = transport.authenticate(qr) { request -> choose(request) }
                Dbg.d(TAG, "authenticate() returned status 0x%02x".format(response[0]))
                runOnUiThread {
                    if (isDestroyed) return@runOnUiThread
                    if (response[0] != 0.toByte() && !failed) {
                        // an answer other than a signature that no step has explained yet
                        val active = states.indexOfFirst { it == State.Active }.takeIf { it >= 0 } ?: Step.Sign.ordinal
                        states[active] = State.Failed("The computer's request could not be handled (CTAP error 0x%02x).".format(response[0]))
                    } else if (!failed && signDetail != null) {
                        // all steps ticked: leave the list and the picture up for a moment
                        states[Step.Sign.ordinal] = State.Done
                        window.decorView.postDelayed({ if (!isFinishing) finish() }, 1000)
                    }
                }
            } catch (e: Exception) {
                Dbg.e(TAG, "authenticate() failed", e)
                val message = if (e is HybridTransport.SignInFailure) e.message ?: "The sign-in failed."
                    else "Something went wrong: ${e.message ?: e.javaClass.simpleName}"
                runOnUiThread {
                    if (!failed && !isDestroyed) {
                        val active = states.indexOfFirst { it == State.Active }.takeIf { it >= 0 } ?: Step.Sign.ordinal
                        states[active] = State.Failed(message)
                    }
                }
            }
        }, "hybrid-sign-in").apply { isDaemon = true }.start()
    }

    // ---- choosing and unlocking -----------------------------------------------------

    /** Runs on the worker thread when the browser's request arrives; blocks until the user decided. */
    private fun choose(request: GetAssertionRequest): Decision {
        val future = CompletableFuture<Decision>()
        pending = future
        runOnUiThread { onRequest(request, future) }
        return try {
            future.get(3, TimeUnit.MINUTES)
        } catch (e: TimeoutException) {
            set(Step.Sign, State.Failed("No passkey was chosen in time."))
            Decision.Denied
        } finally {
            pending = null
        }
    }

    private fun onRequest(request: GetAssertionRequest, future: CompletableFuture<Decision>) {
        // the request only arrives after the key exchange
        states[Step.KeyExchange.ordinal] = State.Done
        states[Step.Sign.ordinal] = State.Active
        val candidates = PasskeyStore(applicationContext).load().filter { request.accepts(it) }
        Dbg.d(TAG, "request for ${request.rpId}, allowList=${request.allowList.size}, candidates=${candidates.size}")
        when (candidates.size) {
            0 -> {
                states[Step.Sign.ordinal] = State.Failed("None of your passkeys is for ${request.rpId}. Import it from Bitwarden first.")
                future.complete(Decision.NoCredentials)
            }
            1 -> unlockAndSign(candidates.single(), candidates)
            else -> choice = candidates
        }
    }

    /** Asks for the screen lock (fingerprint, face or PIN/pattern/password); only then may the worker sign. */
    private fun unlockAndSign(pk: Passkey, candidates: List<Passkey>) {
        val future = pending ?: return
        choice = null
        signDetail = pk.label
        UserUnlock.prompt(
            this,
            title = "Sign in to ${pk.rpName.ifBlank { pk.rpId }}",
            subtitle = pk.label,
            description = "Confirm it's you to sign in on your computer",
            onSuccess = { future.complete(Decision.Sign(pk)) },
            onError = { cancelled, message ->
                if (cancelled && candidates.size > 1) {
                    signDetail = null
                    choice = candidates // back to the choice; the browser keeps waiting
                } else {
                    states[Step.Sign.ordinal] = State.Failed(
                        if (!UserUnlock.available(this)) UserUnlock.NO_SCREEN_LOCK else if (cancelled) "Cancelled." else message,
                    )
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
        transport?.cancel() // ends the worker's wait for the computer at once
        bleAdvertiser?.stop()
        analysisExecutor.shutdown()
        scanner.close()
    }

    // ---- UI -------------------------------------------------------------------------

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun Screen() {
        Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surface)) {
            // upper half: the camera, or what came of the scan
            Box(Modifier.weight(1f).fillMaxWidth().background(Color.Black)) {
                val still = frozen
                if (states[Step.Scan.ordinal] == State.Active) {
                    AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())
                    Viewfinder()
                } else if (still != null) {
                    Magic(
                        still,
                        when {
                            states[Step.Sign.ordinal] == State.Done -> Verdict.Approved
                            failed -> Verdict.Denied
                            else -> Verdict.Verifying
                        },
                    )
                } else {
                    Column(
                        Modifier.fillMaxSize().background(MaterialTheme.colorScheme.primaryContainer),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Icon(AppIcons.QrCodeScanner, null, Modifier.size(72.dp), tint = MaterialTheme.colorScheme.onPrimaryContainer)
                        Spacer(Modifier.height(12.dp))
                        Text(
                            if (scanned) "Sign-in QR code scanned" else "Camera off",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }
                FilledTonalIconButton(onClick = ::cancelAndClose, modifier = Modifier.statusBarsPadding().padding(12.dp)) {
                    Icon(Icons.Rounded.Close, "Cancel")
                }
            }
            // lower half: the steps, live
            Column(Modifier.weight(1f).fillMaxWidth().navigationBarsPadding().padding(horizontal = 24.dp, vertical = 20.dp)) {
                Text("Sign in on your computer", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(16.dp))
                StepRow(Step.Scan, "Scan the QR code", scanHint ?: "Point the camera at the QR code on your computer")
                StepRow(Step.Tunnel, "Open a tunnel" + (tunnelHost?.let { " via $it" } ?: ""), "Encrypted connection through a relay on the internet")
                StepRow(Step.Bluetooth, "Send a Bluetooth broadcast", "So the computer knows this phone is nearby")
                StepRow(Step.KeyExchange, "Noise key exchange", "Waiting for the computer to connect and agree on keys")
                StepRow(Step.Sign, "Sign", signDetail?.let { "As $it, after you unlock" } ?: "Choose a passkey and unlock")
                Spacer(Modifier.weight(1f))
                if (failed) {
                    Row(Modifier.align(Alignment.End)) {
                        if (settingsButton) {
                            androidx.compose.material3.TextButton(onClick = ::openAppSettings) { Text("Open settings") }
                            Spacer(Modifier.width(8.dp))
                        }
                        FilledTonalButton(onClick = ::cancelAndClose) { Text("Close") }
                    }
                }
            }
        }
        choice?.let { candidates ->
            ModalBottomSheet(
                onDismissRequest = { choice = null; set(Step.Sign, State.Failed("Cancelled.")); pending?.complete(Decision.Denied) },
                sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            ) { Choose(candidates) { unlockAndSign(it, candidates) } }
        }
    }

    @Composable
    private fun StepRow(step: Step, title: String, detail: String) {
        val state = states[step.ordinal]
        val scheme = MaterialTheme.colorScheme
        // TalkBack: one item per step, with its state; a failure is announced as it happens
        val spokenState = when (state) {
            State.Pending -> "waiting"
            State.Active -> "in progress"
            State.Done -> "done"
            is State.Failed -> "failed"
        }
        Row(
            Modifier.fillMaxWidth().padding(vertical = 7.dp).semantics(mergeDescendants = true) {
                stateDescription = spokenState
                if (state is State.Failed) liveRegion = LiveRegionMode.Assertive
            },
            verticalAlignment = Alignment.Top,
        ) {
            Box(Modifier.size(28.dp), contentAlignment = Alignment.Center) {
                when (state) {
                    State.Pending -> Box(Modifier.size(22.dp).border(2.dp, scheme.outlineVariant, CircleShape))
                    State.Active -> CircularProgressIndicator(
                        Modifier.size(22.dp), color = StampYellow, trackColor = StampYellow.copy(alpha = 0.25f), strokeWidth = 3.dp,
                    )
                    State.Done -> Box(Modifier.size(24.dp).clip(CircleShape).background(StampGreen), contentAlignment = Alignment.Center) {
                        Icon(Icons.Rounded.Check, null, Modifier.size(16.dp), tint = Color.White)
                    }
                    is State.Failed -> Box(Modifier.size(24.dp).clip(CircleShape).background(StampRed), contentAlignment = Alignment.Center) {
                        Icon(Icons.Rounded.Close, null, Modifier.size(16.dp), tint = Color.White)
                    }
                }
            }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    color = if (state == State.Pending) scheme.onSurfaceVariant else scheme.onSurface,
                )
                val text = when (state) {
                    is State.Failed -> state.message
                    State.Active -> detail
                    else -> null
                }
                if (text != null) Text(
                    text,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (state is State.Failed) StampRed else scheme.onSurfaceVariant,
                )
            }
        }
    }

    /** A sparkle along the QR's edge: where on the perimeter (0..1), how far out, size, timing. */
    private class Sparkle(val along: Float, val out: Float, val size: Float, val phase: Float, val speed: Float)

    /** What the stamp on the scanned code says. */
    private enum class Verdict { Verifying, Approved, Denied }

    /**
     * The frozen scan picture with a "working on it" effect on the QR: the rest
     * dims, the code gets a pulsing outline, a band of light sweeps across it,
     * sparkles twinkle along its edges and a pulsing VERIFYING stamp sits on it.
     * When the outcome is known the code flashes, a shockwave rings out and the
     * stamp is replaced by a green APPROVED or, with a shake, a red DENIED.
     */
    @Composable
    private fun Magic(f: Frozen, verdict: Verdict) {
        var time by remember { mutableFloatStateOf(0f) }
        LaunchedEffect(verdict) {
            if (reduceMotion) return@LaunchedEffect // a still picture: no shimmer, no pulse
            // the clock runs while verifying, and a little longer for the verdict's entrance
            val start = withFrameNanos { it } - (time * 1e9).toLong()
            val until = if (verdict == Verdict.Verifying) Float.MAX_VALUE else time + 1.5f
            while (time < until) withFrameNanos { time = (it - start) / 1e9f }
        }
        // 0 -> 1 as the verdict lands
        val land = remember { Animatable(1f) }
        LaunchedEffect(verdict) {
            if (verdict == Verdict.Verifying) return@LaunchedEffect
            if (reduceMotion) { land.snapTo(1f); return@LaunchedEffect }
            land.snapTo(0f)
            land.animateTo(1f, tween(520, easing = FastOutSlowInEasing))
        }
        val accent = MaterialTheme.colorScheme.primaryContainer
        val yellow = StampYellow
        val gold = Color(0xFFFFD35C)
        val green = StampGreen
        val red = StampRed
        val textMeasurer = rememberTextMeasurer()
        fun measure(word: String, colour: Color) = textMeasurer.measure(
            AnnotatedString(word),
            TextStyle(fontSize = 44.sp, fontWeight = FontWeight.Black, letterSpacing = 3.sp, color = colour),
        )
        val verifyingText = remember(textMeasurer) { measure("VERIFYING", yellow) }
        val approvedText = remember(textMeasurer) { measure("APPROVED", green) }
        val deniedText = remember(textMeasurer) { measure("DENIED", red) }
        val sparkles = remember(f) {
            val rnd = java.util.Random(7)
            List(12) { Sparkle(rnd.nextFloat(), 6f + 22f * rnd.nextFloat(), 5f + 6f * rnd.nextFloat(), rnd.nextFloat(), 0.35f + 0.4f * rnd.nextFloat()) }
        }
        val spoken = when (verdict) {
            Verdict.Verifying -> "Scanned sign-in QR code. Verifying."
            Verdict.Approved -> "Scanned sign-in QR code. Approved: you are signed in on the computer."
            Verdict.Denied -> "Scanned sign-in QR code. Denied."
        }
        Box(Modifier.fillMaxSize().semantics {
            contentDescription = spoken
            liveRegion = LiveRegionMode.Polite
        }) {
            Image(f.image, null, Modifier.fillMaxSize(), contentScale = ContentScale.FillBounds)
            Canvas(Modifier.fillMaxSize().graphicsLayer(compositingStrategy = CompositingStrategy.Offscreen)) {
                // the picture was taken at the view's size; scale in case the layout changed since
                val sx = size.width / f.image.width; val sy = size.height / f.image.height
                val q = f.quad.map { Offset(it.x * sx, it.y * sy) }
                if (q.size < 4) return@Canvas
                val code = Path().apply { moveTo(q[0].x, q[0].y); q.drop(1).forEach { lineTo(it.x, it.y) }; close() }
                val bounds = code.getBounds()
                val centre = bounds.center
                val l = land.value

                drawRect(Color.Black.copy(alpha = 0.4f))
                drawPath(code, Color.Transparent, blendMode = BlendMode.Clear)

                /** A rubber stamp: [text] in a frame on a white backing, rotated, over the code. */
                fun stamp(text: TextLayoutResult, colour: Color, factor: Float, alpha: Float, dx: Float = 0f) {
                    if (alpha <= 0.01f) return
                    val pad = 10.dp.toPx()
                    val w = text.size.width + 2 * pad
                    val h = text.size.height + 2 * pad
                    // one letter size for all three words, fitted to the longest
                    val fit = bounds.width * 0.95f / (verifyingText.size.width + 2 * pad)
                    val k = fit * factor
                    val c = centre + Offset(dx, 0f)
                    withTransform({ rotate(-14f, c); scale(k, k, c) }) {
                        val topLeft = c - Offset(w / 2, h / 2)
                        drawRoundRect(Color.White.copy(alpha = 0.78f * alpha), topLeft, Size(w, h), CornerRadius(10.dp.toPx()))
                        drawRoundRect(
                            colour.copy(alpha = alpha), topLeft, Size(w, h), CornerRadius(10.dp.toPx()),
                            style = Stroke(4.dp.toPx() / fit),
                        )
                        drawText(text, topLeft = c - Offset(text.size.width / 2f, text.size.height / 2f), alpha = alpha)
                    }
                }

                if (verdict != Verdict.Verifying) {
                    val colour = if (verdict == Verdict.Approved) green else red
                    drawPath(code, colour.copy(alpha = 0.9f), style = Stroke(3.dp.toPx(), join = StrokeJoin.Round))
                    if (l < 1f) {
                        // a flash over the code and a shockwave ring in the verdict's colour
                        drawPath(code, Color.White.copy(alpha = 0.85f * (1f - l) * (1f - l)))
                        val reach = maxOf(bounds.width, bounds.height)
                        drawCircle(
                            colour.copy(alpha = 0.8f * (1f - l)), reach * (0.45f + 0.9f * l), centre,
                            style = Stroke((10f * (1f - l) + 1f).dp.toPx()),
                        )
                        // the VERIFYING stamp blows away
                        stamp(verifyingText, yellow, 1f + 0.6f * l, (1f - l) * (1f - l))
                    }
                    // the verdict slams down; DENIED also shakes
                    val shake = if (verdict == Verdict.Denied) sin(l * PI.toFloat() * 7f) * (1f - l) * 14.dp.toPx() else 0f
                    stamp(if (verdict == Verdict.Approved) approvedText else deniedText, colour, 1.8f - 0.8f * l, l, shake)
                    return@Canvas
                }

                // softly pulsing outline
                val pulse = 0.5f + 0.5f * sin(time * 2f * PI.toFloat() / 1.8f)
                drawPath(code, accent.copy(alpha = 0.16f + 0.14f * pulse), style = Stroke(16.dp.toPx(), join = StrokeJoin.Round))
                drawPath(code, accent.copy(alpha = 0.55f + 0.4f * pulse), style = Stroke(2.5.dp.toPx(), join = StrokeJoin.Round))

                // a band of light sweeping diagonally across the code
                val s = -0.4f + 1.8f * ((time / 2.4f) % 1f)
                val c = Offset(bounds.left + bounds.width * s, bounds.top + bounds.height * s)
                val d = Offset(bounds.width * 0.16f, bounds.height * 0.16f)
                clipPath(code) {
                    drawRect(
                        Brush.linearGradient(
                            listOf(Color.Transparent, Color.White.copy(alpha = 0.32f), gold.copy(alpha = 0.18f), Color.Transparent),
                            start = c - d, end = c + d,
                        ),
                        topLeft = bounds.topLeft, size = bounds.size,
                    )
                }

                // sparkles twinkling just outside the edges
                val mid = Offset(q.sumOf { it.x.toDouble() }.toFloat() / 4, q.sumOf { it.y.toDouble() }.toFloat() / 4)
                for (sp in sparkles) {
                    val alpha = sin(2f * PI.toFloat() * (time * sp.speed + sp.phase)).coerceAtLeast(0f).let { it * it * it }
                    if (alpha < 0.02f) continue
                    val e = (sp.along * 4).toInt().coerceIn(0, 3); val t = sp.along * 4 - e
                    val onEdge = q[e] + (q[(e + 1) % 4] - q[e]) * t
                    val dir = (onEdge - mid).let { it / it.getDistance().coerceAtLeast(1f) }
                    val at = onEdge + dir * sp.out.dp.toPx()
                    val r = sp.size.dp.toPx() * (0.6f + 0.4f * alpha)
                    val k = r * 0.22f
                    val star = Path().apply {
                        moveTo(at.x, at.y - r); lineTo(at.x + k, at.y - k); lineTo(at.x + r, at.y); lineTo(at.x + k, at.y + k)
                        lineTo(at.x, at.y + r); lineTo(at.x - k, at.y + k); lineTo(at.x - r, at.y); lineTo(at.x - k, at.y - k); close()
                    }
                    drawPath(star, (if (sp.phase > 0.5f) gold else Color.White).copy(alpha = 0.85f * alpha))
                }

                // the pulsing VERIFYING stamp, on top of the shimmer
                val beat = if (reduceMotion) 1f else 0.5f + 0.5f * sin(time * 2f * PI.toFloat() / 1.1f)
                stamp(verifyingText, yellow, 0.97f + 0.06f * beat, 0.55f + 0.45f * beat)
            }
        }
    }

    @Composable
    private fun Viewfinder() {
        val accent = MaterialTheme.colorScheme.primaryContainer
        Canvas(Modifier.fillMaxSize().graphicsLayer(compositingStrategy = CompositingStrategy.Offscreen)) {
            val side = minOf(size.width, size.height) * 0.68f
            val topLeft = Offset((size.width - side) / 2, (size.height - side) / 2)
            val radius = 28.dp.toPx()
            drawRect(Color.Black.copy(alpha = 0.5f))
            drawRoundRect(Color.Transparent, topLeft, Size(side, side), CornerRadius(radius), blendMode = BlendMode.Clear)
            val arm = side * 0.16f
            val l = topLeft.x; val t = topLeft.y; val r = l + side; val b = t + side
            fun corner(path: Path) = drawPath(path, accent, style = Stroke(5.dp.toPx(), cap = StrokeCap.Round))
            corner(Path().apply { moveTo(l, t + arm); lineTo(l, t + radius); quadraticBezierTo(l, t, l + radius, t); lineTo(l + arm, t) })
            corner(Path().apply { moveTo(r - arm, t); lineTo(r - radius, t); quadraticBezierTo(r, t, r, t + radius); lineTo(r, t + arm) })
            corner(Path().apply { moveTo(l, b - arm); lineTo(l, b - radius); quadraticBezierTo(l, b, l + radius, b); lineTo(l + arm, b) })
            corner(Path().apply { moveTo(r - arm, b); lineTo(r - radius, b); quadraticBezierTo(r, b, r, b - radius); lineTo(r, b - arm) })
        }
    }

    @Composable
    private fun Choose(candidates: List<Passkey>, onPick: (Passkey) -> Unit) {
        val first = candidates.first()
        Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp).navigationBarsPadding()) {
            Text("Choose a passkey", style = MaterialTheme.typography.headlineSmall)
            Text(
                "to sign in to ${first.rpName.ifBlank { first.rpId }} on your computer",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            LazyColumn(verticalArrangement = Arrangement.spacedBy(2.dp), contentPadding = PaddingValues(bottom = 24.dp)) {
                itemsIndexed(candidates) { i, pk ->
                    val big = 20.dp; val small = 4.dp
                    val shape = RoundedCornerShape(
                        topStart = if (i == 0) big else small, topEnd = if (i == 0) big else small,
                        bottomStart = if (i == candidates.lastIndex) big else small,
                        bottomEnd = if (i == candidates.lastIndex) big else small,
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
}
