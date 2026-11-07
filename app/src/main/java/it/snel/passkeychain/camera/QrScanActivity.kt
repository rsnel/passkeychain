package it.snel.passkeychain.camera

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
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
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.ui.AppIcons
import it.snel.passkeychain.ui.theme.PassKeyChainTheme
import java.util.concurrent.Executors

/**
 * Full-screen camera that looks for a QR code and returns its text via
 * [RESULT_QR]. Any QR is returned; the caller decides what to do with it.
 */
class QrScanActivity : ComponentActivity() {

    private val analysisExecutor = Executors.newSingleThreadExecutor()
    private val scanner = BarcodeScanning.getClient()
    private lateinit var previewView: PreviewView
    @Volatile private var delivered = false

    private val requestCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) startCamera() else finishWith(null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        previewView = PreviewView(this).apply { scaleType = PreviewView.ScaleType.FILL_CENTER }
        setContent {
            PassKeyChainTheme {
                ScanScreen(previewView, onClose = { finishWith(null) })
            }
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
            startCamera()
        else requestCamera.launch(Manifest.permission.CAMERA)
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
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
        if (media == null || delivered) { proxy.close(); return }
        val image = InputImage.fromMediaImage(media, proxy.imageInfo.rotationDegrees)
        scanner.process(image)
            .addOnSuccessListener { codes ->
                val qr = codes.firstOrNull { it.format == Barcode.FORMAT_QR_CODE }?.rawValue
                if (qr != null && !delivered) { delivered = true; finishWith(qr) }
            }
            .addOnFailureListener { Log.w("QrScan", "barcode error", it) }
            .addOnCompleteListener { proxy.close() }
    }

    private fun finishWith(qr: String?) {
        if (qr != null) { // closing the scanner without a QR just goes back
            val intent = android.content.Intent(this, it.snel.passkeychain.hybrid.HybridSignInActivity::class.java)
            intent.putExtra("qr_text", qr)
            startActivity(intent)
        }
        setResult(if (qr != null) RESULT_OK else RESULT_CANCELED)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        analysisExecutor.shutdown()
        scanner.close()
    }

    companion object {
        const val RESULT_QR = "qr_text"
        const val RESULT_IS_FIDO = "is_fido"
    }
}

@Composable
private fun ScanScreen(previewView: PreviewView, onClose: () -> Unit) {
    val accent = MaterialTheme.colorScheme.primaryContainer
    Box(Modifier.fillMaxSize()) {
        AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())

        // dimmed overlay with a rounded square cut out, plus corner marks
        Canvas(
            Modifier.fillMaxSize().graphicsLayer(compositingStrategy = CompositingStrategy.Offscreen),
        ) {
            val side = minOf(size.width, size.height) * 0.72f
            val topLeft = Offset((size.width - side) / 2, (size.height - side) / 2.4f)
            val radius = 32.dp.toPx()
            drawRect(Color.Black.copy(alpha = 0.55f))
            drawRoundRect(
                Color.Transparent, topLeft, Size(side, side), CornerRadius(radius), blendMode = BlendMode.Clear,
            )
            val arm = side * 0.16f
            val stroke = 5.dp.toPx()
            val l = topLeft.x; val t = topLeft.y; val r = l + side; val b = t + side
            fun corner(path: Path) = drawPath(path, accent, style = Stroke(stroke, cap = StrokeCap.Round))
            corner(Path().apply { moveTo(l, t + arm); lineTo(l, t + radius); quadraticBezierTo(l, t, l + radius, t); lineTo(l + arm, t) })
            corner(Path().apply { moveTo(r - arm, t); lineTo(r - radius, t); quadraticBezierTo(r, t, r, t + radius); lineTo(r, t + arm) })
            corner(Path().apply { moveTo(l, b - arm); lineTo(l, b - radius); quadraticBezierTo(l, b, l + radius, b); lineTo(l + arm, b) })
            corner(Path().apply { moveTo(r - arm, b); lineTo(r - radius, b); quadraticBezierTo(r, b, r, b - radius); lineTo(r, b - arm) })
        }

        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp)) {
            Row(Modifier.fillMaxWidth()) {
                FilledTonalIconButton(onClick = onClose) { Icon(Icons.Rounded.Close, "Close") }
            }
            Spacer(Modifier.weight(1f))
            Surface(
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(Modifier.padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(AppIcons.QrCodeScanner, null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(16.dp))
                    Column {
                        Text("Scan the sign-in QR", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Point the camera at the QR code that your computer shows when it asks for a passkey.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}
