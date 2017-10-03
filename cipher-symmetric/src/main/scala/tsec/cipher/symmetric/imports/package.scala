package tsec.cipher.symmetric

import tsec.cipher.common._
import tsec.cipher.common.mode.GCM
import tsec.cipher.common.padding.NoPadding
import tsec.common.JKeyGenerator

package object imports{
  type AEADCipherText[A] = CipherText[A, GCM, NoPadding]

  trait CipherKeyGen[A] extends JKeyGenerator[A, SecretKey, CipherKeyBuildError]
}
