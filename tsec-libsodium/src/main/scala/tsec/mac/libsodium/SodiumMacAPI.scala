package tsec.mac.libsodium

import tsec.keygen.symmetric.SymmetricKeyGenAPI
import tsec.mac.MacAPI

trait SodiumMacAPI[A] extends MacAPI[A, SodiumMACKey] with SymmetricKeyGenAPI[A, SodiumMACKey]
