package gadgetinspector.spring;

import gadgetinspector.data.ClassReference;
import gadgetinspector.data.GraphCall;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.data.Source;
import java.util.Map;
import java.util.Set;

public class SpringMVCSourceDiscovery extends HttpServletRequestSourceDiscovery {

  @Override
  public void discover(Map<ClassReference.Handle, ClassReference> classMap,
      Map<MethodReference.Handle, MethodReference> methodMap,
      InheritanceMap inheritanceMap, Map<MethodReference.Handle, Set<GraphCall>> graphCallMap) {

    for (MethodReference.Handle method : methodMap.keySet()) {
      ClassReference classReference = classMap.get(method.getClassReference());
      Set<GraphCall> graphCalls = graphCallMap.get(method);
      if (graphCalls == null) {
        continue;
      }
      for (GraphCall graphCall : graphCalls) {
        if (classReference != null && (classReference.getAnnotations()
            .contains("Lorg/springframework/web/bind/annotation/RestController;") || classReference
            .getAnnotations().contains("Lorg/springframework/stereotype/Controller;"))) {
          addDiscoveredSource(new Source(method, graphCall.getCallerArgIndex()));
          continue;
        }
      }
    }
    super.discover(classMap, methodMap, inheritanceMap, graphCallMap);
  }

}
