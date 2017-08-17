import javax.crypto.Cipher
import cats.implicits._
import tsec.cipher.common.mode.{GCM, ModeKeySpec}
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric.instances._
import tsec.cipher.common._
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra

object PoorMansBenchmark extends App {

  val key: SecretKey[JEncryptionKey[AES128]] = AES128.keyGen.generateKeyUnsafe()

  val p                                                  = PlainText[AES128, GCM, NoPadding]("hellop".getBytes)
  val insOld: JCASymmetricCipher[AES128, GCM, NoPadding] = JCASymmetricCipher.getCipherUnsafe[AES128, GCM, NoPadding]

  val ins: JCAThreadLocal[AES128, GCM, NoPadding] = JCAThreadLocal.getCipherUnsafe[AES128, GCM, NoPadding](10)

  val th = ichi.bench.Thyme.warmed(verbose = print)

  th.pbench(testJCAInstance(),title = "One instance jvm mutable")

  th.pbench(testGCMReg(), title = "Usual library methods")

  th.pbench(testRegular(insOld, p, key), title = "Regular Either interpreter")

  th.pbench(testRegular(ins, p, key), title = "ThreadLocal interpreter")

  def testJCAInstance(): Unit = {
  val jcaIns: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    var i = 0
    while (i < 1000000) {
      jcaIns.init(Cipher.ENCRYPT_MODE, key.key)
      jcaIns.doFinal(p.content)
      i += 1
    }
  }

  def testGCMReg(): Unit = {
    var i = 0
    while (i < 1000000) {
      val kk = Cipher.getInstance("AES/GCM/NoPadding")
      kk.init(Cipher.ENCRYPT_MODE, key.key)
      kk.doFinal(p.content)
      i += 1
    }
  }

  def testRegular[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](
      instance: SymmetricCipherAlgebra[Either[CipherError, ?], A, M, P, JEncryptionKey],
    plaintext: PlainText[A, M, P],
    key: SecretKey[JEncryptionKey[A]]): Unit = {
    var i = 0
    while (i < 1000000) {
      instance.encrypt(plaintext, key)
      i += 1
    }
  }
}
