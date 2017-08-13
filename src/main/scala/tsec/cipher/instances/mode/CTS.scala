package tsec.cipher.instances.mode

sealed trait CTS
object CTS extends DefaultModeKeySpec[CTS]("CTS")
