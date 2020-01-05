package gadgetinspector.fastjson;

import gadgetinspector.SerializableDecider;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.MethodReference;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class FastjsonSerializableDecider implements SerializableDecider {
    public FastjsonSerializableDecider(Map<MethodReference.Handle, MethodReference> methodMap) {
    }

    @Override
    public Boolean apply(ClassReference.Handle handle) {
        return Boolean.TRUE;
    }
}
