package tsec

import java.util.concurrent.TimeUnit
import javax.crypto
import javax.crypto.Cipher

import cats.effect.IO
import org.openjdk.jmh.annotations._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.bouncy._
import tsec.cipher.symmetric.jca.{SecretKey, AES256GCM => JAESGCM}
import tsec.cipher.symmetric.libsodium.{AES256GCM, SodiumKey, XChacha20AEAD}
import tsec.common._
import tsec.libsodium._

@State(Scope.Thread)
@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.MILLISECONDS)
class CipherBench {
  import CipherBench._

  /** Our libsodium setup **/
  implicit lazy val sodium: ScalaSodium = ScalaSodium.getSodiumUnsafe

  /** AES using tsec classes **/
  implicit lazy val jcaAESInstance: AADEncryptor[IO, JAESGCM, SecretKey] =
    JAESGCM.genEncryptor[IO].unsafeRunSync()

  /** Our AES using the JCA raw classes. Note: We reuse cipher the instance for speed, but it's not thread safe **/
  lazy val jcaRAWKey: crypto.SecretKey = SecretKey.toJavaKey(JAESGCM.unsafeGenerateKey)
  lazy val jcaRAWInstance: Cipher      = Cipher.getInstance("AES/GCM/NoPadding")

  @Benchmark
  def testJCARawSideEffecting(): Unit = {
    jcaRAWInstance.init(Cipher.ENCRYPT_MODE, jcaRAWKey)
    jcaRAWInstance.doFinal(longPlaintext)
  }

  @Benchmark
  def testJCARawCreateInstance(): Unit = {
    val j = Cipher.getInstance("AES/GCM/NoPadding")
    j.init(Cipher.ENCRYPT_MODE, jcaRAWKey)
    j.doFinal(longPlaintext)
  }

  /** We test each io action
    * to view the related overhead, but we do not care about sequencing them
    */
  @Benchmark
  def testTSecJCA(): CipherText[JAESGCM] =
    JAESGCM
      .encrypt[IO](longPlaintext, AESGCMKey, Iv[JAESGCM](gcmIv))
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumAES(): CipherText[AES256GCM] =
    AES256GCM
      .encrypt[IO](longPlaintext, SodiumKey[AES256GCM](AESKeyRaw), Iv[AES256GCM](gcmIv))
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumXChacha20(): CipherText[XChacha20AEAD] =
    XChacha20AEAD
      .encrypt[IO](longPlaintext, SodiumKey[XChacha20AEAD](XChaChaKey), Iv[XChacha20AEAD](XChaChaIv))
      .unsafeRunSync()

  @Benchmark
  def testBouncyXChacha20(): CipherText[XChaCha20Poly1305] =
    XChaCha20Poly1305
      .encrypt[IO](longPlaintext, BouncySecretKey[XChaCha20Poly1305](XChaChaKey), Iv[XChaCha20Poly1305](XChaChaIv))
      .unsafeRunSync()
}

object CipherBench {
  lazy val longPlaintext: PlainText = PlainText(Array.fill[Char](5000)(99).mkString.utf8Bytes)

  val XChaChaIv  = "07000000404142434445464748494a4b0000000000000000".hexBytesUnsafe
  val XChaChaKey = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f".hexBytesUnsafe
  val fixedPTRaw = "Ladies and Gentlemen of the class of '99: If I could offer you only one " +
    "tip for the future, sunscreen would be it."
  val fixedPT = PlainText(fixedPTRaw.utf8Bytes)

  val AESKeyRaw = "15d2d85402d913c9342967232c09d29ce5345e54ecc964963256a5d7f5328e4d".hexBytesUnsafe
  val AESGCMKey = JAESGCM.unsafeBuildKey(AESKeyRaw)
  val gcmIv     = "a84da0b22dc35ca5e5507326".hexBytesUnsafe

}
