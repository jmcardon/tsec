package tsec.cipher.symmetric.jca

import tsec.cipher.symmetric._

trait AES192[A] extends AES[A]{
  val keySizeBytes: Int = 24
}