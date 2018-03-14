package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric._

trait AES128[A] extends AES[A] {
  val keySizeBytes: Int = 16
}
