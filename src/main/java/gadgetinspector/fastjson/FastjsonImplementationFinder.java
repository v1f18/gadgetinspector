package gadgetinspector.fastjson;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.data.MethodReference;
import gadgetinspector.data.MethodReference.Handle;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class FastjsonImplementationFinder implements ImplementationFinder {

    private final SerializableDecider serializableDecider;
    private final Map<Handle, Set<Handle>> methodImplMap;

    public FastjsonImplementationFinder(SerializableDecider serializableDecider,
        Map<Handle, Set<Handle>> methodImplMap) {
        this.serializableDecider = serializableDecider;
        this.methodImplMap = methodImplMap;
    }

    @Override
    public Set<MethodReference.Handle> getImplementations(MethodReference.Handle target) {
        Set<MethodReference.Handle> allImpls = new HashSet<>();

        // Fastjson可以指定接口实现类
        allImpls.add(target);

        Set<MethodReference.Handle> subClassImpls = methodImplMap.get(target);
        if (subClassImpls != null) {
            for (MethodReference.Handle subClassImpl : subClassImpls) {
                if (Boolean.TRUE.equals(serializableDecider.apply(subClassImpl.getClassReference()))) {
                    allImpls.add(subClassImpl);
                }
            }
        }

        return allImpls;
    }
}
