package tsec.libsodium

import tsec.common._

case class KeyLengthError(n: Int) extends TSecError {
  val cause = (s"Keylength $n not supported, expected length must be in [${ScalaSodium.crypto_kdf_BYTES_MIN},${ScalaSodium.crypto_kdf_BYTES_MAX}]")
}

case class ContextBytesError(n: Int) extends TSecError {
  val cause: String =
    s"ContextBytes length $n not supported, must be ${ScalaSodium.crypto_kdf_CONTEXTBYTES} bytes long"
}

