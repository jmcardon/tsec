package tsec.cipher.instances.mode

sealed trait CTS
object CTS extends WithModeTag[CTS]("CTS") with DefaultModeKeySpec[CTS]
