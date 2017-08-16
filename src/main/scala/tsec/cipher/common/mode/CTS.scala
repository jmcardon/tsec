package tsec.cipher.common.mode

sealed trait CTS
object CTS extends DefaultModeKeySpec[CTS]("CTS")
