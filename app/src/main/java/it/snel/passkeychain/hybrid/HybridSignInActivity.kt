package it.snel.passkeychain.hybrid

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity

/**
 * A placeholder Activity that takes the scanned FIDO QR code,
 * initializes the BLE Advertiser, and starts broadcasting.
 */
class HybridSignInActivity : ComponentActivity() {

    private val TAG = "HybridSignInActivity"
    private lateinit var bleAdvertiser: AndroidBleAdvertiser
    private lateinit var transport: HybridTransport

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val qrText = intent.getStringExtra("qr_text")
        if (qrText == null) {
            Toast.makeText(this, "No QR text provided", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        try {
            val qr = FidoQr.parse(qrText)
            bleAdvertiser = AndroidBleAdvertiser(this)
            
            // We use a dummy TunnelClient because we haven't implemented it yet.
            val dummyTunnel = object : HybridTransport.TunnelClient {
                override fun connectAndHandshake(tunnelUrl: String, psk: ByteArray, peerIdentity: ByteArray): HybridTransport.TunnelClient.Channel {
                    throw HybridTransport.DeviceStageMissing("Tunnel not implemented yet")
                }
            }
            
            transport = HybridTransport(bleAdvertiser, dummyTunnel)
            
            // For now, we only call deriveKeys and advertise to test the BLE.
            val keys = transport.deriveKeys(qr)
            Log.d(TAG, "Starting BLE advertisement for QR: $qrText")
            bleAdvertiser.advertise(java.util.UUID.fromString("0000FFF9-0000-1000-8000-00805F9B34FB"), keys.eid)
            
            Toast.makeText(this, "Broadcasting BLE. Check Chrome Log.", Toast.LENGTH_LONG).show()
            
        } catch (e: Exception) {
            Log.e(TAG, "Error starting BLE", e)
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::bleAdvertiser.isInitialized) {
            bleAdvertiser.stop()
        }
    }
}
