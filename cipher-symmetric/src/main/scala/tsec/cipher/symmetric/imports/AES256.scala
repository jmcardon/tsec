package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric.core.AES

trait AES256[A] extends AES[A] {
  val keySizeBytes: Int = 32
}
