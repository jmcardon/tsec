import javax.crypto.Cipher

import cats.Monad
import cats.effect.IO
import cats.implicits._
import tsec.cipher.common.mode.{GCM, ModeKeySpec}
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric.instances._
import tsec.cipher.common._
import scala.util.Random

/**
  * Ugly as shit but effective benchmarking code
  */
object PoorMansBenchmark extends App{
  val totalIterLen = 100000

  val keys: Array[SecretKey[JEncryptionKey[AES128]]] = Array.fill(totalIterLen)(AES128.keyGen.generateKeyUnsafe())

  val rand = new Random()

  val plaintexts: Array[PlainText[AES128, GCM, NoPadding]] =
    Array.fill(totalIterLen)(PlainText[AES128, GCM, NoPadding](("hellop" + rand.nextInt(1000)).getBytes()))

  val eitherInterpreter: JCASymmetricCipher[AES128, GCM, NoPadding] =
    JCASymmetricCipher.getCipherUnsafe[AES128, GCM, NoPadding]

  val eThreadLocalInterpreter: JCASymmetricImpure[AES128, GCM, NoPadding] =
    JCASymmetricImpure.getCipherUnsafe[AES128, GCM, NoPadding](10)

  val ioThreadLocalInterpreter: JCAThreadLocalIO[AES128, GCM, NoPadding] =
    JCAThreadLocalIO.getCipher[AES128, GCM, NoPadding]().unsafeRunSync()
  val jcaInstance: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
  val th                  = ichi.bench.Thyme.warmed(verbose = print)

  /*
  Our first two arrays are for JCA plain output, unboxed, untyped
   */
  val regularTest = new Array[Array[Byte]](totalIterLen)
  val gmreg       = new Array[Array[Byte]](totalIterLen)

  /*
  Our next two, for Our boxed, effect-handled computations
   */
  val bench1Array = new Array[Either[CipherError, CipherText[AES128, GCM, NoPadding]]](totalIterLen)
  val bench2Array = new Array[Either[CipherError, CipherText[AES128, GCM, NoPadding]]](totalIterLen)

  /*
  How the hell to bench IO?
   */
  val bench3Array = new Array[CipherText[AES128, GCM, NoPadding]](totalIterLen)

//  th.pbenchOff(title = "JCA one mutable instance vs threadLocal")(
//    testJCAInstance()
//  )({
//    var i = 0
//    while (i < totalIterLen) {
//      bench2Array(i) = eThreadLocalInterpreter.encrypt(plaintexts(i), keys(i))
//      i += 1
//    }
//  })

  th.pbench(testJCAInstance(), title = "One instance jvm mutable")

  th.pbench(testGCMReg(), title = "Usual library methods")

  th.pbench({
    var i = 0
    while (i < totalIterLen) {
      bench1Array(i) = eitherInterpreter.encrypt(plaintexts(i), keys(i))
      i += 1
    }
  }, title = "Regular Either interpreter")

  th.pbench({
    var i = 0
    while (i < totalIterLen) {
      bench2Array(i) = eThreadLocalInterpreter.encrypt(plaintexts(i), keys(i))
      i += 1
    }
  }, title = "ThreadLocal interpreter")

  th.pbench(testIO(),title = "Symmetric IO interpreter")


  /**
    * This is an ideal scenario, wherein you'd have only _one_ instance of
    * your cipher, wherein you save the expensive alloc
    *
    */
  def testJCAInstance(): Unit = {
    var i = 0
    while (i < totalIterLen) {
      jcaInstance.init(Cipher.ENCRYPT_MODE, keys(i).key)
      regularTest(i) = jcaInstance.doFinal(plaintexts(i).content)
      i += 1
    }
  }

  /**
    *
    * This is similar to what security libraries on the JVM abstract away
    * from you
    */
  def testGCMReg(): Unit = {
    var i = 0
    while (i < totalIterLen) {
      val kk = Cipher.getInstance("AES/GCM/NoPadding")
      kk.init(Cipher.ENCRYPT_MODE, keys(i).key)
      gmreg(i) = kk.doFinal(plaintexts(i).content)
      i += 1
    }
  }

  /**
   * We test each io action
   * to view the related overhead, but we do not care about sequencing them
   *
   */
  def testIO(): Unit = {
    var i = 0
    while (i < totalIterLen){
      ioThreadLocalInterpreter.encrypt(plaintexts(i), keys(i))
          .map(f => {
            bench3Array(i) = f
          })
        .unsafeRunSync()
      i +=1
    }
  }
}
