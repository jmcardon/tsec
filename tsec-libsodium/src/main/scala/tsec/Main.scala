package tsec

import cats.effect.IO
import tsec.common._
import org.apache.commons.codec.binary._
import tsec.cipher.symmetric.PlainText
import tsec.cipher.symmetric.libsodium.{SodiumCipherText, XSalsa20Poly1305}
import cats.syntax.all._

/** Experimental example scratch file
  *
  */
object Main extends App {


//  val arrayBytes = new Array[Byte](ScalaSodium.CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES)

//  val pw    = "hihi!".utf8Bytes
//  val pwOut = new Array[Byte](ScalaSodium.crypto_pwhash_STRBYTES.toInt)
//  sodium.crypto_pwhash_str(
//    pwOut,
//    pw,
//    pw.length + 3,
//    ScalaSodium.crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
//    ScalaSodium.crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
//  )
//  println(Hex.encodeHexString(pwOut))
//  println(sodium.crypto_pwhash_str_verify(pwOut, pw, pw.length))
//
//  val outArray = new Array[Byte](ScalaSodium.crypto_generichash_blake2b_BYTES)

//  sodium.crypto_generichash_blake2b(outArray, ScalaSodium.crypto_generichash_blake2b_BYTES, pw, pw.length, null, 0)
//
//  print(outArray.toHexString)

//  sodium.crypto_aead_chacha20poly1305_keygen(arrayBytes)
//  println(Hex.encodeHexString(arrayBytes))

//  implicit val sodium = ScalaSodium.ScalaSodium
//
//  val program: IO[(SodiumCipherText[XSalsa20Poly1305], PlainText)] = for {
//    key       <- XSalsa20Poly1305.generateKey[IO]
//    encrypted <- XSalsa20Poly1305.encrypt[IO](PlainText("sup jimbo".utf8Bytes), key)
//    decrypted <- XSalsa20Poly1305.decrypt[IO](encrypted, key)
//  } yield (encrypted, decrypted)

  import tsec.jni._

//  val bytes = new Array[Byte](20)
//  println(bytes.toHexString)
//  ScalaSodium.randombytes_buf(bytes, bytes.length)
//  println(bytes.toHexString)
//  program.unsafeRunSync()

}
