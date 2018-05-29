package tsec.cipher.symmetric

import tsec.common.ArrayHKNewt

package object bouncy {

  type BouncySecretKey[A] = BouncySecretKey.Type[A]

  object BouncySecretKey extends ArrayHKNewt

}
