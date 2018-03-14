package tsec.cipher.symmetric.libsodium.internal

import tsec.cipher.symmetric.AuthCipherAPI
import tsec.cipher.symmetric.libsodium._

trait SodiumCipherAPI[A] extends AuthCipherAPI[A, SodiumKey]
