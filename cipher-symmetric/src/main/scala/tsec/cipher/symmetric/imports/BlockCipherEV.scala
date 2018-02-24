package tsec.cipher.symmetric.imports

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{KeyGenerator => KG}

import cats.Id
import cats.effect.Sync
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.BlockCipher
import tsec.keygen.symmetric._

/** A Helper type for providing implicit evidence that some type
  * A represents AES.
  *
  */
private[tsec] trait JCAKeyGen[A] extends SymmetricKeyGenAPI[A, SecretKey] {
  private def keySizeBits(implicit B: BlockCipher[A]) = B.keySizeBytes * 8

  private def generator(implicit B: BlockCipher[A]): KG = KG.getInstance(B.cipherName)

  implicit def newKeyGen[F[_]](implicit F: Sync[F], B: BlockCipher[A]): SymmetricKeyGen[F, A, SecretKey] =
    new SymmetricKeyGen[F, A, SecretKey] {
      def generateKey: F[SecretKey[A]] = F.delay(impl.unsafeGenerateKey)

      def build(rawKey: Array[Byte]): F[SecretKey[A]] = F.delay(impl.unsafeBuild(rawKey))
    }

  implicit def idKeyGen(implicit B: BlockCipher[A]): IdKeyGen[A, SecretKey] = new IdKeyGen[A, SecretKey] {
    def generateKey: Id[SecretKey[A]] = impl.unsafeGenerateKey

    def build(rawKey: Array[Byte]): Id[SecretKey[A]] = impl.unsafeBuild(rawKey)
  }

  private[tsec] object impl {
    def unsafeGenerateKey(implicit B: BlockCipher[A]): SecretKey[A] = {
      val gen = generator
      gen.init(keySizeBits)
      SecretKey[A](gen.generateKey())
    }

    def unsafeBuild(rawKey: Array[Byte])(implicit B: BlockCipher[A]): SecretKey[A] =
      if (rawKey.length != B.keySizeBytes)
        throw CipherKeyBuildError("Incorrect key length")
      else
        SecretKey[A](
          new SecretKeySpec(rawKey, B.cipherName)
        )
  }
}

/** A helper class for a block cipher type C which
  * carried information about key size
  */
protected[tsec] class BlockCipherEV[A](val cipherName: String, val blockSizeBytes: Int, val keySizeBytes: Int)
    extends BlockCipher[A]
    with JCAKeyGen[A] {

  implicit val BlockCipher: BlockCipher[A] = this
}
