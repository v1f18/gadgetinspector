package gadgetinspector.sqlinject;

import gadgetinspector.data.ClassReference;
import gadgetinspector.data.GraphCall;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.spring.SpringMVCSourceDiscovery;
import java.util.Map;
import java.util.Set;

public class SQLInjectSourceDiscovery extends SpringMVCSourceDiscovery {

  @Override
  public void discover(Map<ClassReference.Handle, ClassReference> classMap,
      Map<MethodReference.Handle, MethodReference> methodMap,
      InheritanceMap inheritanceMap, Map<MethodReference.Handle, Set<GraphCall>> graphCallMap) {
    super.discover(classMap, methodMap, inheritanceMap, graphCallMap);
  }

}
