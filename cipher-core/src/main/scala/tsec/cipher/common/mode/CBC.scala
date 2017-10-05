package tsec.cipher.common.mode

sealed trait CBC

/** our cbc mode takes 16 byte IVs
  * https://crypto.stackexchange.com/questions/2594/initialization-vector-length-insufficient-in-aes
  */
object CBC extends DefaultModeKeySpec[CBC]("CBC", 16)
