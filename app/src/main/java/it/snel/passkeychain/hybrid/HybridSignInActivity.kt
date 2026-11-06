package it.snel.passkeychain.hybrid

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import it.snel.passkeychain.store.PasskeyStore

class HybridSignInActivity : ComponentActivity() {
    private val TAG = "HybridSignInActivity"
    private lateinit var bleAdvertiser: AndroidBleAdvertiser
    private lateinit var transport: HybridTransport

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val qrText = intent.getStringExtra("qr_text")
        if (qrText == null) { Toast.makeText(this, "No QR text", Toast.LENGTH_SHORT).show(); finish(); return }

        try {
            val qr = FidoQr.parse(qrText)
            Log.d(TAG, "qr.peerPublicKey = " + qr.peerPublicKey.joinToString("") { "%02X".format(it) })
            Log.d(TAG, "qr.qrSecret      = " + qr.qrSecret.joinToString("") { "%02X".format(it) })

            val store = PasskeyStore(applicationContext)
            val passkey = store.load().firstOrNull()
            if (passkey == null) { Toast.makeText(this, "Import a passkey first", Toast.LENGTH_LONG).show(); finish(); return }

            bleAdvertiser = AndroidBleAdvertiser(this)
            transport = HybridTransport(bleAdvertiser, NoiseTunnelClient())

            Log.d(TAG, "Starting hybrid authenticate() for QR: $qrText")
            Thread {
                try { transport.authenticate(qr, passkey); Log.d(TAG, "authenticate() returned") }
                catch (e: Exception) { Log.e(TAG, "authenticate() failed", e) }
                finally { runOnUiThread { Toast.makeText(this, "Hybrid flow finished. See logcat.", Toast.LENGTH_LONG).show() } }
            }.start()

            Toast.makeText(this, "Connecting tunnel...", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Log.e(TAG, "Error", e); Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show(); finish()
        }
    }

    override fun onDestroy() { super.onDestroy(); if (::bleAdvertiser.isInitialized) bleAdvertiser.stop() }
}
