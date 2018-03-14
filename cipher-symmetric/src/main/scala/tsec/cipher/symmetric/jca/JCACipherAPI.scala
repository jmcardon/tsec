package tsec.cipher.symmetric.jca

import tsec.cipher.symmetric.CipherAPI

trait JCACipherAPI[A, M, P] extends CipherAPI[A, SecretKey]
