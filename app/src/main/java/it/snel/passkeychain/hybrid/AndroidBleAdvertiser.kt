package it.snel.passkeychain.hybrid

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.ParcelUuid
import it.snel.passkeychain.hybrid.HybridTransport.SignInFailure
import it.snel.passkeychain.util.Dbg
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Android implementation of the caBLE v2 BLE Advertiser.
 * Uses the FIDO caBLE service UUID (0xFFF9) and high TX power.
 *
 * [advertise] waits for Android to confirm that the broadcast started, and
 * throws a [SignInFailure] that says what to do when it did not. Call it from
 * a worker thread: Android answers on the main thread.
 */
class AndroidBleAdvertiser(private val context: Context) : HybridTransport.BleAdvertiser {

    private val TAG = "AndroidBleAdvertiser"
    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager.adapter
    private var advertiser: android.bluetooth.le.BluetoothLeAdvertiser? = null
    private var callback: AdvertiseCallback? = null

    override fun advertise(serviceUuid: UUID, payload: ByteArray) {
        val adapter = bluetoothAdapter ?: throw SignInFailure("This phone has no Bluetooth.")
        if (!adapter.isEnabled) throw SignInFailure("Bluetooth is off. Switch it on and scan the QR code again.")
        val le = adapter.bluetoothLeAdvertiser
            ?: throw SignInFailure("This phone cannot send the Bluetooth Low Energy broadcast that the sign-in needs.")

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceData(ParcelUuid(serviceUuid), payload)
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .build()

        Dbg.d(TAG, "Starting BLE advertisement with UUID $serviceUuid")
        Dbg.d(TAG, "Advertising payload hex: ${payload.joinToString("") { "%02X".format(it) }} (size: ${payload.size})")

        val started = CompletableFuture<Int>() // 0 = started, otherwise Android's error code
        val cb = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Dbg.i(TAG, "BLE advertisement started successfully.")
                started.complete(0)
            }

            override fun onStartFailure(errorCode: Int) {
                Dbg.e(TAG, "BLE advertisement failed to start. Error code: $errorCode")
                started.complete(errorCode)
            }
        }
        try {
            le.startAdvertising(settings, data, cb)
        } catch (e: SecurityException) {
            throw SignInFailure("PassKeyChain may not use Bluetooth. Allow \"Nearby devices\" in the app's settings.", e)
        }
        synchronized(this) {
            advertiser = le
            callback = cb
        }

        val result = try {
            started.get(5, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            // no answer yet: some phones are slow to report; carry on, the computer will tell
            Dbg.w(TAG, "No confirmation of the BLE advertisement after 5 s; continuing")
            return
        }
        when (result) {
            0, AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED -> return
            AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> {
                stop()
                throw SignInFailure(
                    "Bluetooth is busy: other apps are already broadcasting. Close apps that use Bluetooth, " +
                        "or switch Bluetooth off and on, and scan the QR code again.",
                )
            }
            AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> {
                stop()
                throw SignInFailure("This phone cannot send the Bluetooth Low Energy broadcast that the sign-in needs.")
            }
            AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE -> {
                stop()
                throw SignInFailure("This phone refused the Bluetooth broadcast (too large). Please report this.")
            }
            else -> { // ADVERTISE_FAILED_INTERNAL_ERROR and anything newer
                stop()
                throw SignInFailure("Bluetooth reported an error ($result). Switch Bluetooth off and on and scan the QR code again.")
            }
        }
    }

    /** Stops the broadcast; safe to call more than once, from any thread. */
    @Synchronized
    override fun stop() {
        val cb = callback ?: return
        Dbg.d(TAG, "Stopping BLE advertisement.")
        try {
            advertiser?.stopAdvertising(cb)
        } catch (e: Exception) {
            Dbg.w(TAG, "Stopping BLE advertisement failed: ${e.message}")
        }
        advertiser = null
        callback = null
    }
}
