package tsec

import tsec.common.ArrayHKNewt

package object signature {

  type CryptoSignature[A] = CryptoSignature.Type[A]

  object CryptoSignature extends ArrayHKNewt

}
