package tsec

import tsec.NaCl.Sodium
import tsec.common._
import org.apache.commons.codec.binary._

object Main extends App{

  val sodium = ScalaSodium.Sodium
  val arrayBytes = new Array[Byte](Sodium.CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES)

  val pw = "hihi!".utf8Bytes
  val pwOut = new Array[Byte](Sodium.crypto_pwhash_STRBYTES)
  sodium.crypto_pwhash_str(pwOut, pw, pw.length, Sodium.crypto_pwhash_OPSLIMIT_SENSITIVE, Sodium.crypto_pwhash_MEMLIMIT_SENSITIVE)
  println(Hex.encodeHexString(pwOut))
  println(sodium.crypto_pwhash_str_verify(pwOut, pw, pw.length))
//  sodium.crypto_aead_chacha20poly1305_keygen(arrayBytes)
//  println(Hex.encodeHexString(arrayBytes))

}
