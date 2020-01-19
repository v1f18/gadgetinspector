package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.fastjson.FastjsonImplementationFinder;
import gadgetinspector.fastjson.FastjsonSerializableDecider;
import gadgetinspector.fastjson.FastjsonSourceDiscovery;
import gadgetinspector.sqlinject.fastjson.SQLInjectImplementationFinder;
import gadgetinspector.sqlinject.fastjson.SQLInjectSerializableDecider;
import gadgetinspector.sqlinject.fastjson.SQLInjectSourceDiscovery;
import java.util.Map;
import java.util.Set;

public class SQLInjectDeserializationConfig implements GIConfig {

    @Override
    public String getName() {
        return "sqlinject";
    }

    @Override
    public SerializableDecider getSerializableDecider(Map<MethodReference.Handle, MethodReference> methodMap, InheritanceMap inheritanceMap) {
        return new SQLInjectSerializableDecider(methodMap);
    }

    @Override
    public ImplementationFinder getImplementationFinder(Map<MethodReference.Handle, MethodReference> methodMap,
                                                        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap,
                                                        InheritanceMap inheritanceMap) {
        return new SQLInjectImplementationFinder(methodImplMap);
    }

    @Override
    public SourceDiscovery getSourceDiscovery() {
        return new SQLInjectSourceDiscovery();
    }
}
