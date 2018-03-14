package tsec.cipher.symmetric.jca

import tsec.cipher.symmetric.AEADAPI

trait JCAAEAD[A, M, P] extends AEADAPI[A, SecretKey]
