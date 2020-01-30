package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.SlinkDiscovery;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.sqlinject.SQLInjectImplementationFinder;
import gadgetinspector.sqlinject.SQLInjectSerializableDecider;
import gadgetinspector.sqlinject.SQLInjectSourceDiscovery;
import gadgetinspector.sqlinject.mybatis.MapperXMLDiscovery;
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

    @Override
    public SlinkDiscovery getSlinkDiscovery() {
        return new MapperXMLDiscovery();
    }
}
