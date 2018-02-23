package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric.core.AES

trait AES192[A] extends AES[A]{
  val keySizeBytes: Int = 24
}