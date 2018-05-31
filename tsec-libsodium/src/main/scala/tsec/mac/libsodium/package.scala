package tsec.mac

import tsec.common.ArrayHKNewt

package object libsodium {

  type SodiumMACKey[A] = SodiumMACKey.Type[A]

  object SodiumMACKey extends ArrayHKNewt

}
