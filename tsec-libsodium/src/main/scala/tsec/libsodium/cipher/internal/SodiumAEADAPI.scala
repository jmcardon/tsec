package tsec.libsodium.cipher.internal

import tsec.cipher.symmetric.core._
import tsec.libsodium.cipher.SodiumKey

trait SodiumAEADAPI[A] extends AEADAPI[A, SodiumKey]
