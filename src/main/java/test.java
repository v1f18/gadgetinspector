import java.io.IOException;

public class test {
        public String name = "v1f18";
    public String main(String args) throws IOException {

        String cmd = new A().method1(args);
        return new B().method2(cmd,name);
    }
}
class A {
    public A(){

    }
    public String method1(String param) {
        return param;
    }
}
class B {
    public String method2(String param,String name) {
        return new C().method3(param,name);
    }
}
class C {
    public String method3(String param,String name) {
        return param+name;
    }
}

