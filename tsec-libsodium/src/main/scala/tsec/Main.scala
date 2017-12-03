package tsec

import tsec.jni.SodiumJNI
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher.XChacha20Poly1305
import tsec.common._
import cats.effect._
import cats.syntax.all._
import fs2._

object Main extends App {

  implicit val sodium = ScalaSodium.getSodiumUnsafe

  val kekkeron =
    s"""
       | hellooooooooooooooooooooooooooooooooooooooooo
       | my name is fred
       | are you fred
       | i am fred
       | kek
     """.stripMargin.utf8Bytes

  val st = Stream.emits(kekkeron).covary[IO]

  val pipeAndHeader = for {
    key  <- XChacha20Poly1305.generateKey[IO]
    pipe <- XChacha20Poly1305.encryptionPipeAndHeader[IO](key, 3)
  } yield (key, pipe._1, pipe._2)

  val (key, header, encpipe) = pipeAndHeader.unsafeRunSync()

  val decpipe = XChacha20Poly1305.decryptionPipe[IO](header, key, 3)

  val out = Stream
    .emits(kekkeron)
    .covary[IO]
    .through(encpipe)
    .through(decpipe)
    .runLog
    .map(_.toArray)
    .unsafeRunSync()

//  val sst = Stream
//    .emits(out)
//    .covary[IO]
//    .through(decpipe)
//    .runLog
//    .map(_.toArray.toUtf8String)
//    .unsafeRunSync()
//
  println(out.toUtf8String)

}
