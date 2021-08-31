package com.example.pgptest

import android.os.Bundle
import android.view.LayoutInflater
import androidx.appcompat.app.AppCompatActivity
import com.example.pgptest.databinding.ActivityMainBinding
import java.security.KeyPairGenerator

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val binding = ActivityMainBinding.inflate(LayoutInflater.from(this))
        setContentView(binding.root)

        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "SC")
        val keyPair = keyPairGenerator.genKeyPair()
        
        val pgpSecretKey = keyPair.asPGP("first", "privet")
        binding.etPrivateKey.setText(pgpSecretKey.toASCIIString())
        binding.etPublicKey.setText(pgpSecretKey.publicKey.toASCIIString())
    }
}
