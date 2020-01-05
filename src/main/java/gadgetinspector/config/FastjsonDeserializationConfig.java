package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.fastjson.FastjsonImplementationFinder;
import gadgetinspector.fastjson.FastjsonSerializableDecider;
import gadgetinspector.fastjson.FastjsonSourceDiscovery;
import gadgetinspector.jackson.JacksonImplementationFinder;
import gadgetinspector.jackson.JacksonSerializableDecider;
import gadgetinspector.jackson.JacksonSourceDiscovery;
import java.util.Map;
import java.util.Set;

public class FastjsonDeserializationConfig implements GIConfig {

    @Override
    public String getName() {
        return "fastjson";
    }

    @Override
    public SerializableDecider getSerializableDecider(Map<MethodReference.Handle, MethodReference> methodMap, InheritanceMap inheritanceMap) {
        return new FastjsonSerializableDecider(methodMap);
    }

    @Override
    public ImplementationFinder getImplementationFinder(Map<MethodReference.Handle, MethodReference> methodMap,
                                                        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap,
                                                        InheritanceMap inheritanceMap) {
        return new FastjsonImplementationFinder(getSerializableDecider(methodMap, inheritanceMap));
    }

    @Override
    public SourceDiscovery getSourceDiscovery() {
        return new FastjsonSourceDiscovery();
    }
}
