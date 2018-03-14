package tsec.cipher.symmetric.libsodium.internal

import tsec.cipher.symmetric.libsodium.SodiumKey
import tsec.cipher.symmetric.AEADAPI

trait SodiumAEADAPI[A] extends AEADAPI[A, SodiumKey]
