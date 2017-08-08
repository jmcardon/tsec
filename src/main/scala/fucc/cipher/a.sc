
import fucc.cipher.{CipherError, CipherText, ClearText}
import fucc.cipher.instance._
import fucc.symmetric.instances._


implicit val k = DESInstance.generateKey()

val plain: ClearText = ClearText("abcdef".getBytes)


val x = for {
  enc <- `DES/ECB/PKCS5Padding`.encrypt(plain)
  dec <- `DES/ECB/PKCS5Padding`.decrypt(enc)
} yield dec

x match {
  case Right(msg) => println(s"Wroks : ${msg.content}")
  case Left(msg) => println("fails...")
}