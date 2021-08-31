package com.example.pgptest

import org.spongycastle.bcpg.ArmoredOutputStream
import org.spongycastle.bcpg.HashAlgorithmTags
import org.spongycastle.openpgp.*
import org.spongycastle.openpgp.operator.jcajce.*
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.SecureRandom
import java.util.*

fun KeyPair.asPGP(
    identity: String,
    passPhrase: String
): PGPSecretKey {
    val sha1Calc = JcaPGPDigestCalculatorProviderBuilder().build()[HashAlgorithmTags.SHA1]
    val keyPair: PGPKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, this, Date())
    return PGPSecretKey(
        PGPSignature.DEFAULT_CERTIFICATION,
        keyPair,
        identity,
        sha1Calc,
        null,
        null,
        JcaPGPContentSignerBuilder(keyPair.publicKey.algorithm, HashAlgorithmTags.SHA1),
        JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)
            .setProvider(SPONGY_CASTLE_PROVIDER)
            .build(passPhrase.toCharArray())
    )
}

fun PGPPublicKey.toASCIIString(): String {
    val out = ByteArrayOutputStream()
    val armoredOut = ArmoredOutputStream(out)
    encode(armoredOut)
    armoredOut.close()
    return out.toByteArray().decodeToString()
}

fun PGPSecretKey.toASCIIString(): String {
    val out = ByteArrayOutputStream()
    val armoredOut = ArmoredOutputStream(out)
    encode(armoredOut)
    armoredOut.close()
    return out.toByteArray().decodeToString()
}

fun PGPPublicKey.buildEncryptedDataGenerator(withIntegrityCheck: Boolean): PGPEncryptedDataGenerator {
    val dataEncryptorBuilder = JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
        .setWithIntegrityPacket(withIntegrityCheck)
        .setSecureRandom(SecureRandom())
        .setProvider(SPONGY_CASTLE_PROVIDER)
    val encryptedDataGenerator = PGPEncryptedDataGenerator(dataEncryptorBuilder)
    val encryptionMethodGenerator = JcePublicKeyKeyEncryptionMethodGenerator(this)
        .setProvider(SPONGY_CASTLE_PROVIDER)
    encryptedDataGenerator.addMethod(encryptionMethodGenerator)
    return encryptedDataGenerator
}

fun PGPEncryptedDataGenerator.encryptToASCIIArmoredString(data: ByteArray): String {
    val out = ByteArrayOutputStream()
    val armoredOut = ArmoredOutputStream(out)
    val encryptedOut = open(armoredOut, data.size.toLong())
    encryptedOut.write(data)
    encryptedOut.close()
    armoredOut.close()
    return out.toByteArray().decodeToString()
}

const val SPONGY_CASTLE_PROVIDER = "SC"
