package tsec

import tsec.common.ArrayHKNewt

package object hashing {

  type CryptoHash[A] = CryptoHash.Type[A]

  object CryptoHash extends ArrayHKNewt

}
