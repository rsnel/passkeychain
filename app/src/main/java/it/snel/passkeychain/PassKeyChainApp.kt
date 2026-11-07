package it.snel.passkeychain

import android.app.Application
import it.snel.passkeychain.util.Dbg

class PassKeyChainApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Dbg.init(this)
    }
}
