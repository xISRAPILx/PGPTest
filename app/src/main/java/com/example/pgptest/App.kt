package com.example.pgptest

import android.app.Application
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class App : Application() {
    override fun onCreate() {
        super.onCreate()

        Security.addProvider(BouncyCastleProvider())
    }
}
