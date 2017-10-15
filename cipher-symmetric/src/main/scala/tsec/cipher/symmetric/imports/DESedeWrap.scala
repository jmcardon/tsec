package tsec.cipher.symmetric.imports

sealed trait DESedeWrap
object DESedeWrap extends WithAEADCipher[DESedeWrap]("DESedeWrap", 164)
