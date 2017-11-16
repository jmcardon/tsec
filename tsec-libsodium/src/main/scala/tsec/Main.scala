package tsec

import tsec.common._
import org.apache.commons.codec.binary._

/** Experimental example scratch file
  *
  */
object Main extends App {

  val sodium = ScalaSodium.Sodium
//  val arrayBytes = new Array[Byte](ScalaSodium.CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES)

  val pw    = "hihi!".utf8Bytes
  val pwOut = new Array[Byte](ScalaSodium.crypto_pwhash_STRBYTES.toInt)
  sodium.crypto_pwhash_str(
    pwOut,
    pw,
    pw.length + 3,
    ScalaSodium.crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
    ScalaSodium.crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
  )
  println(Hex.encodeHexString(pwOut))
  println(sodium.crypto_pwhash_str_verify(pwOut, pw, pw.length))

  val outArray = new Array[Byte](ScalaSodium.crypto_generichash_blake2b_BYTES)

//  sodium.crypto_generichash_blake2b(outArray, ScalaSodium.crypto_generichash_blake2b_BYTES, pw, pw.length, null, 0)
//
//  print(outArray.toHexString)

//  sodium.crypto_aead_chacha20poly1305_keygen(arrayBytes)
//  println(Hex.encodeHexString(arrayBytes))

}
