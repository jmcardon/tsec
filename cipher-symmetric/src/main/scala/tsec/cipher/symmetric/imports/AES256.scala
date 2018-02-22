package tsec.cipher.symmetric.imports

trait AES256[A] extends AESEV[A]{
  val keySizeBytes: Int = 32
}
