package tsec.cipher.symmetric.imports

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{KeyGenerator => KG}

import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.{AES, BlockCipher}
import tsec.keygen.symmetric.SymmetricKeyGen

/** A helper class for a block cipher type C which
  * carried information about key size
  */
protected[tsec] class BlockCipherEV[C](val cipherName: String, val blockSizeBytes: Int, val keySizeBytes: Int)
    extends BlockCipher[C]
    with SymmetricKeyGen[C, SecretKey, DummyImplicit] {

  implicit val tag: BlockCipher[C] = this

  private def keySizeBits = keySizeBytes * 8

  private def generator: KG = KG.getInstance(cipherName)

  def unsafeGenerate(implicit S: DummyImplicit): SecretKey[C] = {
    val gen = generator
    gen.init(keySizeBits)
    SecretKey[C](gen.generateKey())
  }

  def unsafeBuild(rawKey: Array[Byte])(implicit S: DummyImplicit): SecretKey[C] =
    if (rawKey.length != keySizeBytes)
      throw CipherKeyBuildError("Incorrect key length")
    else
      SecretKey[C](
        new SecretKeySpec(rawKey, cipherName)
      )
}

/** A Helper type for providing implicit evidence that some type
  * A represents AES.
  *
  */
private[tsec] trait AESEV[A] extends AES[A] with SymmetricKeyGen[A, SecretKey, DummyImplicit] {
  implicit val ev: AES[A] = this

  private def keySizeBits = keySizeBytes * 8

  private def generator: KG = KG.getInstance(cipherName)

  def unsafeGenerate(implicit S: DummyImplicit): SecretKey[A] = {
    val gen = generator
    gen.init(keySizeBits)
    SecretKey[A](gen.generateKey())
  }

  def unsafeBuild(rawKey: Array[Byte])(implicit S: DummyImplicit): SecretKey[A] =
    if (rawKey.length != keySizeBytes)
      throw CipherKeyBuildError("Incorrect key length")
    else
      SecretKey[A](
        new SecretKeySpec(rawKey, cipherName)
      )
}
