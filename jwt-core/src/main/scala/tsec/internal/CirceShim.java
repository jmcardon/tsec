package tsec.internal;

import io.circe.JsonObject$;

public class CirceShim {

    public static io.circe.JsonObject fromLinkedHashMap(java.util.LinkedHashMap<String, io.circe.Json> map) {
        return JsonObject$.MODULE$.fromLinkedHashMap(map);
    }

}
