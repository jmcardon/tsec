package tsec.cipher.symmetric.jca

import tsec.cipher.symmetric._

trait AES256[A] extends AES[A] {
  val keySizeBytes: Int = 32
}
