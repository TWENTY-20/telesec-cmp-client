package de.twenty20.cmp.response

import de.twenty20.cmp.CmpClientException
import de.twenty20.cmp.TelesecClient
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.bouncycastle.asn1.crmf.EncryptedKey
import org.bouncycastle.asn1.crmf.EncryptedValue
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class ResponseAnalyser(
    private val subRaCertificate: X509Certificate,
    private val subRaPrivateKey: PrivateKey,
) {
    val logger: Logger = LogManager.getLogger(TelesecClient::class.java) // Uses same logger as TelesecClient

    fun decryptKey(key: EncryptedKey?): PrivateKey? {
        if (key == null) return null

        // EncryptedValueParse can't figure out how to decrypt cipher so we do it manually
        val ev = EncryptedValue.getInstance(key)

        // 1. decrypt symmetric key
        val transformation = when(val pk = subRaCertificate.publicKey) {
            is RSAPublicKey -> "RSA/ECB/PKCS1Padding"
            is ECPublicKey -> "ECIES"
            else -> throw CmpClientException("Unexpected key type for sub ra public key: ${pk.algorithm}")
        }
        val cipher = Cipher.getInstance(transformation).apply {
            init(Cipher.DECRYPT_MODE, subRaPrivateKey)
        }
        val symmetricKey = cipher.doFinal(ev.encSymmKey.bytes)

        // the AES key is 128 bit long
        val secretKeySpec = SecretKeySpec(symmetricKey.copyOf(16), "AES")

        // 2. decrypt private key
        val aes = Cipher.getInstance("AES/CBC/PKCS5Padding")
        aes.init(
            Cipher.DECRYPT_MODE,
            secretKeySpec,
            IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        )
        return JcaPEMKeyConverter().getPrivateKey(PrivateKeyInfo.getInstance(aes.doFinal(ev.encValue.bytes)))
    }


    companion object {
        val CERT_TYPE = Regex("(?<=CertType\\?).*?(?=%)")
        val CERT_PWD = Regex("(?<=RevocationPwd\\?).*?(?=%)")
    }
}