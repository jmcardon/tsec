package tsec.libsodium.cipher.internal

import tsec.cipher.symmetric.AEADAPI
import tsec.libsodium.cipher.SodiumKey

trait SodiumAEADAPI[A] extends AEADAPI[A, SodiumKey]
