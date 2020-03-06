package snyk;

import soot.Scene;

import java.io.IOException;

public class SootMain {
    public static void main(String[] args) throws IOException {
        SootCommandLineArguments cla = SootCommandLineArguments.parseArguments(args);

        String suppliedClassPath = ClasspathUtils.getClasspathFromFile(cla.getClassPathFile());
        Scene analysisOutput  = SootCha.runClassHierarchyAnalysis(cla.getFirstPartyDirectory(), suppliedClassPath);

        if (cla.getCallGraphFilePath().isPresent()) {
            String callGraphPath = cla.getCallGraphFilePath().get();
            SootPrinters.printCallGraph(callGraphPath, analysisOutput.getCallGraph());
        }

        SootPrinters.printClasses(cla.getReachableClassesFilePath(), analysisOutput.getCallGraph());
        SootPrinters.printMethods(cla.getReachableMethodsFilePath(), analysisOutput.getCallGraph());

        System.out.println("All done");
    }
}
