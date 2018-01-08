package tsec.cipher.symmetric.imports

import cats.effect.Sync
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric.imports.primitive.JCAAEADPrimitive

sealed abstract class AESGCMConstruction[A: AES] extends JCAAEAD[A, GCM, NoPadding, GCMCipherText[A]] {

  def genEncryptor[F[_]: Sync]: F[GCMEncryptor[F, A]] = JCAAEADPrimitive[F, A, GCM, NoPadding]()

  /** Our default Iv strategy for GCM mode
    * produces randomized IVs
    *
    *
    * @return
    */
  def defaultIvStrategy: GCMIVStrategy[A] = GCM.randomIVStrategy[A]

}

object AES128GCM extends AESGCMConstruction[AES128]

object AES192GCM extends AESGCMConstruction[AES192]

object AES256GCM extends AESGCMConstruction[AES256]
