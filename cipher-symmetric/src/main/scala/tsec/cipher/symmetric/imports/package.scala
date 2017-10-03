package tsec.cipher.symmetric

import tsec.cipher.common.CipherText
import tsec.cipher.common.mode.GCM
import tsec.cipher.common.padding.NoPadding

package object imports{
  type AEADCipherText[A] = CipherText[A, GCM, NoPadding]
}
