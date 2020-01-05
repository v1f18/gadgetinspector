package gadgetinspector;

import gadgetinspector.config.ConfigRepository;
import gadgetinspector.config.GIConfig;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.PatternLayout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Main entry point for running an end-to-end analysis. Deletes all data files before starting and writes discovered
 * gadget chains to gadget-chains.txt.
 */
public class GadgetInspector {
    private static final Logger LOGGER = LoggerFactory.getLogger(GadgetInspector.class);

    private static void printUsage() {
        System.out.println("Usage:\n  Pass either a single argument which will be interpreted as a WAR, or pass " +
                "any number of arguments which will be intepretted as a list of JARs forming a classpath.");

    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        //配置log4j用于输出日志
        configureLogging();

        boolean resume = false;
        //fuzz类型，默认java原生序列化
        GIConfig config = ConfigRepository.getConfig("jserial");

        int argIndex = 0;
        while (argIndex < args.length) {
            String arg = args[argIndex];
            if (!arg.startsWith("--")) {
                break;
            }
            if (arg.equals("--resume")) {
                //不删除dat文件
                resume = true;
            } else if (arg.equals("--config")) {
                //--config参数指定fuzz类型
                config = ConfigRepository.getConfig(args[++argIndex]);
                if (config == null) {
                    throw new IllegalArgumentException("Invalid config name: " + args[argIndex]);
                }
            } else {
                throw new IllegalArgumentException("Unexpected argument: " + arg);
            }

            argIndex += 1;
        }

        final ClassLoader classLoader;
        //程序参数的最后一部分，即最后一个具有前缀--的参数（例：--resume）后
        if (args.length == argIndex+1 && args[argIndex].toLowerCase().endsWith(".war")) {
            //加载war文件
            Path path = Paths.get(args[argIndex]);
            LOGGER.info("Using WAR classpath: " + path);
            //实现为URLClassLoader，加载war包下的WEB-INF/lib和WEB-INF/classes
            classLoader = Util.getWarClassLoader(path);
        } else {
            //加载jar文件，java命令后部，可配置多个
            final Path[] jarPaths = new Path[args.length - argIndex];
            for (int i = 0; i < args.length - argIndex; i++) {
                Path path = Paths.get(args[argIndex + i]).toAbsolutePath();
                if (!Files.exists(path)) {
                    throw new IllegalArgumentException("Invalid jar path: " + path);
                }
                jarPaths[i] = path;
            }
            LOGGER.info("Using classpath: " + Arrays.toString(jarPaths));
            //实现为URLClassLoader，加载所有指定的jar
            classLoader = Util.getJarClassLoader(jarPaths);
        }
        //类枚举加载器，具有两个方法
        //getRuntimeClasses获取rt.jar的所有class
        //getAllClasses获取rt.jar以及classLoader加载的class
        final ClassResourceEnumerator classResourceEnumerator = new ClassResourceEnumerator(classLoader);

        //删除所有的dat文件
        if (!resume) {
            // Delete all existing dat files
            LOGGER.info("Deleting stale data...");
            for (String datFile : Arrays.asList("classes.dat", "methods.dat", "inheritanceMap.dat",
                    "passthrough.dat", "callgraph.dat", "sources.dat", "methodimpl.dat")) {
                final Path path = Paths.get(datFile);
                if (Files.exists(path)) {
                    Files.delete(path);
                }
            }
        }

        //扫描java runtime所有的class（rt.jar）和指定的jar或war中的所有class

        // Perform the various discovery steps
        if (!Files.exists(Paths.get("classes.dat")) || !Files.exists(Paths.get("methods.dat"))
                || !Files.exists(Paths.get("inheritanceMap.dat"))) {
            LOGGER.info("Running method discovery...");
            MethodDiscovery methodDiscovery = new MethodDiscovery();
            methodDiscovery.discover(classResourceEnumerator);
            //保存了类信息、方法信息、继承实现信息
            methodDiscovery.save();
        }

        if (!Files.exists(Paths.get("passthrough.dat"))) {
            LOGGER.info("Analyzing methods for passthrough dataflow...");
            PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
            //记录参数在方法调用链中的流动关联（如：A、B、C、D四个方法，调用链为A->B B->C C->D，其中参数随着调用关系从A流向B，在B调用C过程中作为入参并随着方法结束返回，最后流向D）
            //该方法主要是追踪上面所说的"B调用C过程中作为入参并随着方法结束返回"，入参和返回值之间的关联
            passthroughDiscovery.discover(classResourceEnumerator, config);
            passthroughDiscovery.save();
        }

        if (!Files.exists(Paths.get("callgraph.dat"))) {
            LOGGER.info("Analyzing methods in order to build a call graph...");
            CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
            //记录参数在方法调用链中的流动关联（如：A、B、C三个方法，调用链为A->B B->C，其中参数随着调用关系从A流向B，最后流C）
            //该方法主要是追踪上面所说的参数流动，即A->B入参和B->C入参的关系，以确定参数可控
            callGraphDiscovery.discover(classResourceEnumerator, config);
            callGraphDiscovery.save();
        }

        if (!Files.exists(Paths.get("sources.dat"))) {
            LOGGER.info("Discovering gadget chain source methods...");
            SourceDiscovery sourceDiscovery = config.getSourceDiscovery();
            //查找利用链的入口（例：java原生反序列化的readObject）
            sourceDiscovery.discover();
            sourceDiscovery.save();
        }

        {
            LOGGER.info("Searching call graph for gadget chains...");
            GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery(config);
            //根据上面的数据收集，最终分析利用链
            gadgetChainDiscovery.discover();
        }

        LOGGER.info("Analysis complete!");
    }

    private static void configureLogging() {
        ConsoleAppender console = new ConsoleAppender();
        String PATTERN = "%d %c [%p] %m%n";
        console.setLayout(new PatternLayout(PATTERN));
        console.setThreshold(Level.DEBUG);
        console.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(console);
    }
}
