package tsec.libsodium

package object kdf {

  case class KeyLengthError(n: Int) extends Exception with Product with Serializable {
    def cause: String =
      s"Keylength $n not supported, expected length must be in [${ScalaSodium.crypto_kdf_BYTES_MIN},${ScalaSodium.crypto_kdf_BYTES_MAX}]"

    override def fillInStackTrace(): Throwable = this
  }

  case class ContextBytesError(n: Int) extends Exception with Product with Serializable {
    def cause: String =
      s"ContextBytes length $n not supported, must be ${ScalaSodium.crypto_kdf_CONTEXTBYTES} bytes long"

    override def fillInStackTrace(): Throwable = this
  }

}
