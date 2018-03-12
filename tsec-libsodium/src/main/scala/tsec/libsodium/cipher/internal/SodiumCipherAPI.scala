package tsec.libsodium.cipher.internal

import tsec.cipher.symmetric.core._
import tsec.libsodium.cipher.SodiumKey

trait SodiumCipherAPI[A] extends AuthCipherAPI[A, SodiumKey]
