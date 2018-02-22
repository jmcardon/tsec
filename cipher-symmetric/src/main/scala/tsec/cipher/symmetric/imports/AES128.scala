package tsec.cipher.symmetric.imports

trait AES128[A] extends AESEV[A] {
  val keySizeBytes: Int = 16
}
