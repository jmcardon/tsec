package tsec.kdf.libsodium

import tsec.common._
import tsec.libsodium.ScalaSodium

case class KeyLengthError(n: Int) extends TSecError {
  val cause =
    s"Keylength $n not supported, expected length must be in " +
      s"[${ScalaSodium.crypto_kdf_BYTES_MIN},${ScalaSodium.crypto_kdf_BYTES_MAX}]"
}

case class ContextBytesError(n: Int) extends TSecError {
  val cause: String =
    s"ContextBytes length $n not supported, must be ${ScalaSodium.crypto_kdf_CONTEXTBYTES} bytes long"
}
