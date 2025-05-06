package de.twenty20.cmp.request

@Suppress("unused")
sealed class CertType(vararg val usage: CertUsage) {
    data object Gateway : CertType(CertUsage.GATEWAY)
    data object Server : CertType(CertUsage.SERVER)

    sealed class User(vararg usage: CertUsage) : CertType(*usage) {
        data object SingleKey : User(CertUsage.SIGNATURE)
        data object DualKey : User(CertUsage.SIGNATURE, CertUsage.ENCRYPTION)
        data object TripleKey : User(CertUsage.SIGNATURE, CertUsage.ENCRYPTION, CertUsage.WIN_LOGON)
    }

    enum class CertUsage(val typename: String) {
        GATEWAY("Gateway"),
        SERVER("Server"),
        SIGNATURE("Signature"),
        ENCRYPTION("Encryption"),
        WIN_LOGON("WinLogon"),
    }
}