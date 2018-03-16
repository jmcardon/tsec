package tsec.build

object GenSodiumPlugin extends sbt.AutoPlugin {
  import sbt._

  override def requires = empty
  override def trigger = allRequirements

  object autoImport {
    lazy val gensodium = taskKey[Unit]("Generate ScalaSodium0.scala")
  }
  import autoImport._

  override def buildSettings = Seq(
    /* See plugins.sbt for why this is dynamically loaded */
    gensodium := Def.task {
      if (canWeUseComSunTools_?) {
        getClass.getClassLoader
          .loadClass("tsec.build.GenSodium")
          .getMethod("main", classOf[Array[String]])
          .invoke(null, Array.empty[String])
      } else {
        sys.error("sodium \"macro\" not supported on your superior JDK, sorry")
      }
    }
  )

  lazy val canWeUseComSunTools_? = ( // yes, iff ...
       // we're not in IntelliJ
       !sys.env.getOrElse("XPC_SERVICE_NAME", "").toLowerCase.contains("intellij")
       // and we're on oracle JDK (sorry Mr Stallman)
    && sys.props.get("java.vendor").exists(_.toLowerCase.contains("oracle"))
  )

}
