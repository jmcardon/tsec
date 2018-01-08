package tsec.cipher.symmetric.imports

import cats.effect.Sync
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric.core.IvStrategy
import tsec.cipher.symmetric.imports.primitive.JCAPrimitiveCipher

sealed abstract class AESCTRConstruction[A: AES] extends JCACipher[A, CTR, NoPadding, CTRCipherText[A]] {

  def genEncryptor[F[_]: Sync]: F[CTREncryptor[F, A]] = JCAPrimitiveCipher[F, A, CTR, NoPadding]()

  /** Our default Iv strategy for CTR mode
    * produces randomized IVs
    *
    *
    * @return
    */
  def defaultIvStrategy: IvStrategy[A, CTR] = IvStrategy.defaultStrategy[A, CTR]

}

object AES128CTR extends AESCTRConstruction[AES128]

object AES192CTR extends AESCTRConstruction[AES192]

object AES256CTR extends AESCTRConstruction[AES256]
