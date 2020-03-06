package snyk;

import com.google.common.collect.ImmutableList;
import soot.*;
import soot.options.Options;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

class SootCha {

    static Scene runClassHierarchyAnalysis(
            String firstPartyCodeFolder,
            String suppliedClassPath) {

        System.out.println("Running CHA");
        Options options = G.v().soot_options_Options();

        // we exclude java internals, same as WALA
        ImmutableList<String> exclusions = ImmutableList.of("java.", "javax.", "sun.");
        Options.v().set_exclude(exclusions);
        Options.v().set_no_bodies_for_excluded(true);

        // this sets the exclusion lists to empty, i.e. we don't exclude anything
        // options.set_include_all(true);

        // we need to add jdk to the classpath, otherwise soot complains
        List<String> javaJars = getAllJREJarsPaths("/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home");
        List<String> classPathList = new ArrayList<>(javaJars);
        classPathList.add(suppliedClassPath);
        String fullClassPath = String.join(File.pathSeparator, classPathList);

        // these sets entry points + class path. Since we specify the analysis to be `library`,
        // the entry-points will be all methods of first-party code. We assume all of them are
        // reachable, i.e. all first-party methods are reachable
        options.set_process_dir(ImmutableList.of(firstPartyCodeFolder));
        options.set_soot_classpath(fullClassPath);
        options.setPhaseOption("cg", "library:any-subtype");
        options.setPhaseOption("cg", "all-reachable:true");

        // these just make output nice and readable
        options.set_output_format(Options.output_format_none);
        options.setPhaseOption("jb", "use-original-names:true");

        // should scan classes recursively when creating class hierarchy
        options.set_whole_program(true);

        // we don't need this option for 1st party analysis when we analyze all jars (no gluing),
        // but might want it later
        options.set_allow_phantom_refs(true);

        // probably we want this eventually, the below adds ALL static initializers, and all constructors if Soot
        // can't determine which one to use. This means the call-graph is massive.
        //options.setPhaseOption("cg", "safe-forname:true");
        //options.setPhaseOption("cg", "safe-newinstance:true");

        // this enables call graph CHA analysis
        options.setPhaseOption("cg.cha", "enabled:true");
        options.setPhaseOption("cg.cha", "verbose:true");

        // these runs the analysis
        Scene scene = Scene.v();
        loadAll3rdPartyClasses(scene, suppliedClassPath);

        scene.loadNecessaryClasses();
        System.out.println("Loaded classes");

        PackManager.v().runPacks();
        System.out.println("Finished the analysis");
        return scene;
    }

    private static List<String> getAllJREJarsPaths(String jrePath) {
        File jreDir = new File(jrePath);
        File[] dirFiles = jreDir.listFiles();
        if (dirFiles == null) {
            return ImmutableList.of();
        }

        List<String> jarsInCurDir = Arrays.stream(dirFiles)
                .filter(file -> (file.getName().endsWith(".jar") | file.getName().endsWith(".jmod")))
                .map(File::getAbsolutePath)
                .collect(Collectors.toList());

        List<String> jarsInSubDirs = Arrays.stream(dirFiles)
                .filter(File::isDirectory)
                .flatMap(file -> getAllJREJarsPaths(file.getAbsolutePath()).stream())
                .collect(Collectors.toList());

        return ImmutableList.<String>builder()
                .addAll(jarsInCurDir)
                .addAll(jarsInSubDirs)
                .build();
    }

    // Loads all 3rd-party classes available on the classpath. This is due to a limitation of Soot - by default it
    // would only load classes which are references by the entry points of the analysis (+ JVM classes). As a result,
    // when doing CHA, it could miss implementations which are not directly accessible by root classes (e.g. Spring).
    private static void loadAll3rdPartyClasses(Scene scene, String suppliedClassPath) {
        for (String classPathFile : suppliedClassPath.split(File.pathSeparator)) {
            if (!classPathFile.endsWith("jar")) {
                continue;
            }
            for (String className : SourceLocator.v().getClassesUnder(classPathFile)) {
                scene.loadClassAndSupport(className);
            }
        }
    }

}
