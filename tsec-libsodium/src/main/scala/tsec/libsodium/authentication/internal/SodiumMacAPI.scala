package tsec.libsodium.authentication.internal

import tsec.keygen.symmetric.SymmetricKeyGenAPI
import tsec.libsodium.authentication.SodiumMACKey
import tsec.mac.core.MacAPI

trait SodiumMacAPI[A] extends MacAPI[A, SodiumMACKey] with SymmetricKeyGenAPI[A, SodiumMACKey]
