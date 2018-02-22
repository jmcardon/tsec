package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric.core._

trait JCAAEAD[A, M, P] extends AEADApi[A, SecretKey]
