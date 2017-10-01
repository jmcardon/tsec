package tsec.cipher.common.mode

sealed trait OFBx
object OFBx extends DefaultModeKeySpec[OFBx]("OFBx", 16)
