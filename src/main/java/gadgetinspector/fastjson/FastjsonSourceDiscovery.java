package gadgetinspector.fastjson;

import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.data.Source;
import java.util.Collection;
import java.util.Map;

public class FastjsonSourceDiscovery extends SourceDiscovery {

  @Override
  public void discover(Map<ClassReference.Handle, ClassReference> classMap,
      Map<MethodReference.Handle, MethodReference> methodMap,
      InheritanceMap inheritanceMap) {

    final FastjsonSerializableDecider serializableDecider = new FastjsonSerializableDecider(
        methodMap);

    for (MethodReference.Handle method : methodMap.keySet()) {
      if (serializableDecider.apply(method.getClassReference())) {
        if (method.getName().startsWith("get") && method.getDesc().startsWith("()")) {
          if (method.getDesc().matches("\\(L[^;]*;\\)L.+?;")) {
            String fieldName =
                method.getName().charAt(3) + method.getName().substring(4);
            String desc = method.getDesc()
                .substring(method.getDesc().indexOf(")L") + 2, method.getDesc().length() - 1);
            MethodReference.Handle handle = new MethodReference.Handle(
                method.getClassReference(), "set" + fieldName, desc);
            if (!methodMap.containsKey(handle) &&
                method.getDesc().matches("\\(L[^;]*;\\)Ljava/util/Collection;") ||
                method.getDesc().matches("\\(L[^;]*;\\)Ljava/util/Map;") ||
                method.getDesc().matches("\\(L[^;]*;\\)Ljava/util/concurrent/atomic/AtomicBoolean;") ||
                method.getDesc().matches("\\(L[^;]*;\\)Ljava/util/concurrent/atomic/AtomicInteger;") ||
                method.getDesc().matches("\\(L[^;]*;\\)Ljava/util/concurrent/atomic/AtomicLong;")){
              addDiscoveredSource(new Source(method, 0));
            }
          }
        }
        if (method.getName().startsWith("set") && method.getDesc().matches("\\(L[^;]*;\\)V")) {
          addDiscoveredSource(new Source(method, 1));
        }
      }
    }
  }

}
