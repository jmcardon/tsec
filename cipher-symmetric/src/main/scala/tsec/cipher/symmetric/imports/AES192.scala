package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric._

trait AES192[A] extends AES[A]{
  val keySizeBytes: Int = 24
}