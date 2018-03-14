package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric.AEADAPI

trait JCAAEAD[A, M, P] extends AEADAPI[A, SecretKey]
