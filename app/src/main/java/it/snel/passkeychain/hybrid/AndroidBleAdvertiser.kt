package it.snel.passkeychain.hybrid

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

/**
 * Android implementation of the caBLE v2 BLE Advertiser.
 * Uses the FIDO caBLE service UUID (0xFFF9) and high TX power.
 */
class AndroidBleAdvertiser(private val context: Context) : HybridTransport.BleAdvertiser {

    private val TAG = "AndroidBleAdvertiser"
    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager.adapter
    private var advertiser: android.bluetooth.le.BluetoothLeAdvertiser? = null

    override fun advertise(serviceUuid: UUID, payload: ByteArray) {
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled) {
            Log.e(TAG, "Bluetooth is not available or enabled.")
            throw HybridTransport.DeviceStageMissing("Bluetooth not available")
        }

        advertiser = bluetoothAdapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.e(TAG, "BLE Advertising is not supported on this device.")
            throw HybridTransport.DeviceStageMissing("BLE Advertising not supported")
        }

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

        val hexString = payload.joinToString("") { String.format("%02X", it) }
        Log.d(TAG, "Advertising payload hex: $hexString")
        Log.d(TAG, "Starting BLE advertisement with UUID $serviceUuid and ${payload.size} bytes")
        
        advertiser?.startAdvertising(settings, data, object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.i(TAG, "BLE advertisement started successfully.")
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e(TAG, "BLE advertisement failed to start. Error code: $errorCode")
            }
        })
    }

    override fun stop() {
        Log.d(TAG, "Stopping BLE advertisement.")
        advertiser?.stopAdvertising(object : AdvertiseCallback() {})
        advertiser = null
    }
}
