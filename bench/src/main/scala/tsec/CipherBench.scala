package tsec

import java.util.concurrent.TimeUnit
import javax.crypto
import javax.crypto.Cipher

import cats.effect.IO
import org.openjdk.jmh.annotations._
import tsec.cipher.symmetric.jca.{SecretKey, AES256GCM => JAESGCM}
import tsec.cipher.symmetric.{AADEncryptor, IvGen, _}
import tsec.common._
import tsec.libsodium._
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.aead.AES256GCM

import scala.util.Random

@State(Scope.Thread)
@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.MILLISECONDS)
class CipherBench {

  /** Our libsodium setup **/
  implicit lazy val sodium: ScalaSodium            = ScalaSodium.getSodiumUnsafe
  lazy val chachaKey: SodiumKey[XChacha20Poly1305] = XChacha20Poly1305.unsafeGenerateKey
  lazy val sodiumAESKey: SodiumKey[AES256GCM]      = AES256GCM.unsafeGenerateKey

  /** AES using tsec classes **/
  lazy val jcaAESKey: SecretKey[JAESGCM] = JAESGCM.unsafeGenerateKey
  implicit lazy val jcaAESInstance: AADEncryptor[IO, JAESGCM, SecretKey] =
    JAESGCM.genEncryptor[IO].unsafeRunSync()
  implicit lazy val ivStrategy: IvGen[IO, JAESGCM]  = JAESGCM.defaultIvStrategy[IO]
  implicit lazy val ivStrat2: IvGen[IO, AES256GCM] = AES256GCM.defaultIvGen[IO]
  implicit lazy val ivStrat3: IvGen[IO, XChacha20Poly1305] = XChacha20Poly1305.defaultIvGen[IO]

  /** Our AES using the JCA raw classes. Note: We reuse cipher the instance for speed, but it's not thread safe **/
  lazy val jcaRAWKey: crypto.SecretKey = SecretKey.toJavaKey(JAESGCM.unsafeGenerateKey)
  lazy val jcaRAWInstance: Cipher      = Cipher.getInstance("AES/GCM/NoPadding")

  /** Our random plaintext **/
  lazy val longPlaintext: PlainText = PlainText(Array.fill[Char](5000)(Random.nextInt(127).toChar).mkString.utf8Bytes)
  lazy val nPlaintext: PlainText    = PlainText(longPlaintext)

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
  def testTSecJCA(): Unit =
    JAESGCM
      .encrypt[IO](longPlaintext, jcaAESKey)
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumAES(): Unit =
    AES256GCM
      .encrypt[IO](nPlaintext, sodiumAESKey)
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumXChacha20(): Unit =
    XChacha20Poly1305
      .encrypt[IO](nPlaintext, chachaKey)
      .unsafeRunSync()

}
