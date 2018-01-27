package tsec.cipher.symmetric.imports

sealed trait AES256

object AES256 extends AESEV[AES256](32)
