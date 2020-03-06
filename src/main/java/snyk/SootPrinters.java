package snyk;

import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SootClass;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.util.Chain;
import soot.util.queue.QueueReader;

import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

@SuppressWarnings("unused")
class SootPrinters {

    static void printClasses(Scene scene) throws IOException {
        Chain<SootClass> classes = scene.getClasses();
        //Hierarchy classHierarchy = scene.getActiveHierarchy();

        try (FileWriter writer = new FileWriter("soot-class-hierarchy.txt")) {
            for (SootClass aClass : classes) {
                String className = aClass.toString();
                writer.write(" " + className + "\n");
            }
        }
    }

    static void printMethods(String outputPath, CallGraph cg) throws IOException {
        try (FileWriter writer = new FileWriter(outputPath)) {
            QueueReader<Edge> listener = cg.listener();

            Set<String> methods = new HashSet<>();

            while (listener.hasNext()) {
                Edge next = listener.next();

                String sourceStr = methodString(next.getSrc());
                methods.add(sourceStr);

                String targetStr = methodString(next.getTgt());
                methods.add(targetStr);
            }

            for (String method : methods) {
                writer.write(method + "\n");
            }
        }
    }

    private static String methodString(MethodOrMethodContext momc) {
        String functionName = momc.method().getName();
        String className = momc.method().getDeclaringClass().getName();
        return className + "." + functionName;
    }

    static void printCallGraph(String outputPath, CallGraph cg) throws IOException {
        try (FileWriter writer = new FileWriter(outputPath)) {
            QueueReader<Edge> listener = cg.listener();

            // some edges are repeated, we wont print them multiple times
            Set<String> alreadyPrinted = new HashSet<>();

            while (listener.hasNext()) {
                Edge next = listener.next();

                MethodOrMethodContext src = next.getSrc();
                MethodOrMethodContext tgt = next.getTgt();

                String srcString = src.toString();
                String tgtString = tgt.toString();

                String line = " " + srcString + " -> " + tgtString + "\n";
                if (!alreadyPrinted.contains(line)) {
                    alreadyPrinted.add(line);
                    writer.write(line);
                }
            }
        }
    }
}
