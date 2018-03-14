package tsec.libsodium.cipher.internal

import tsec.cipher.symmetric.AuthCipherAPI
import tsec.libsodium.cipher.SodiumKey

trait SodiumCipherAPI[A] extends AuthCipherAPI[A, SodiumKey]
