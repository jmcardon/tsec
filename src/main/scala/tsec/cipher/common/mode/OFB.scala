package tsec.cipher.common.mode

sealed trait OFB
object OFB extends DefaultModeKeySpec[OFB]("OFB")
