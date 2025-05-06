package de.twenty20

import de.twenty20.cmp.TelesecClient
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.BeforeAll
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security

open class TestBase {

    companion object {

        lateinit var CLIENT: TelesecClient
        lateinit var KEY_GEN: KeyPairGenerator

        @BeforeAll
        @JvmStatic
        fun setup() {
            Security.addProvider(BouncyCastleProvider())

            val caPass = TestBase::class.java.getResource("/mvpn_rci_op_ks.pass")?.readText() ?: ""
            val subRaPass = TestBase::class.java.getResource("/mvpn_rci_sub_ra_op_ks.pass")?.readText() ?: ""

            CLIENT = TelesecClient(
                "https://sbca2.test.telesec.de/sbca/cmp",
                KeyStore.getInstance("PKCS12").apply {
                    load(
                        TestBase::class.java.getResourceAsStream("/mvpn_rci_op_ks.p12"),
                        caPass.toCharArray()
                    )
                },
                caPass,
                KeyStore.getInstance("PKCS12").apply {
                    load(
                        TestBase::class.java.getResourceAsStream("/mvpn_rci_sub_ra_op_ks.p12"),
                        subRaPass.toCharArray()
                    )
                },
                subRaPass,
            )

            KEY_GEN = KeyPairGenerator.getInstance("RSA").apply {
                initialize(3072)
            }
        }
    }
}