package snyk;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

// COPY-PASTE FROM WALA
public class ClasspathUtils {
    /**
     * Sanitize a classpath. Given a file that contain the classpath that comes from Maven or Gradle,
     * verify that the files added to the String classpath (.jars, folders, .class) exist. Also looks for jars within
     * the directories found in the classpath, recursively.
     * @param filePath the file path that contains the classpath to be sanitized
     * @return a String with each entry of the classpath separated with ":"
     * @throws IOException
     */
    public static String getClasspathFromFile(final String filePath) throws IOException {
        final StringBuilder classPath = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                final String[] jars = line.split(File.pathSeparator);
                for (String jar : jars) {
                    final File classPathFile = new File(jar);
                    if (!classPathFile.exists()) {
                        continue;
                    }
                    if (classPathFile.getName().endsWith(".jar")
                            || classPathFile.getName().endsWith(".class")) {
                        classPath.append(classPathFile.getAbsolutePath()).append(File.pathSeparator);
                    } else if (classPathFile.isDirectory()) {
                        classPath.append(classPathFile.getAbsolutePath()).append(File.pathSeparator);
                        final String jarFromClassPath = getJarsAsClasspathFromFolder(classPathFile);
                        if ( !jarFromClassPath.isEmpty() ) {
                            classPath.append(jarFromClassPath).append(File.pathSeparator);
                        }
                    }
                }
            }
        }

        return classPath.toString();
    }

    /**
     * Get a String containing all the jars (.jar files) from a directory separated by ":", recursively.
     * @param directory the directory File where the jars are going to fetched from.
     * @return a String containing all the jars (.jar files) from a directory separated by ":"
     */
    private static String getJarsAsClasspathFromFolder(final File directory) {
        final StringBuilder classPath = new StringBuilder();
        final File[] classesDirFiles = directory.listFiles();

        if ( classesDirFiles == null ) {
            return classPath.toString();
        }

        for (final File f : classesDirFiles) {
            if ( f.isDirectory() ) {
                classPath.append(getJarsAsClasspathFromFolder(f));
            } else if (f.getName().endsWith(".jar")) {
                classPath.append(f.getAbsolutePath()).append(File.pathSeparator);
            }
        }

        return classPath.toString();
    }
}
