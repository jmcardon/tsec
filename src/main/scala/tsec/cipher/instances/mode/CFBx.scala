package tsec.cipher.instances.mode

sealed trait CFBx
object CFBx extends WithModeTag[CFBx]("CFBx") with DefaultModeKeySpec[CFBx]
