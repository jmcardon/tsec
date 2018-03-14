package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric.CipherAPI

trait JCACipherAPI[A, M, P] extends CipherAPI[A, SecretKey]
