package snyk;

import org.apache.commons.cli.*;
import java.util.Optional;

 class SootCommandLineArguments {
    private CommandLineParser parser;
    private CommandLine commandLine;
    private Options options;

    private static String CLASSPATH_FILE_PARAMETER_NAME = "classpath";
    private static String FIRST_PARTY_DIRECTORY = "firstpary";

    private static String REACHABLE_METHODS_FILEPATH_PARAMETER_NAME = "methods_out";
    private static String CALL_GRAPH_FILEPATH_PARAMETER_NAME = "cg_out";

    private SootCommandLineArguments() {
        parser = new DefaultParser();
        options = new Options();
    }

    static SootCommandLineArguments parseArguments(String[] arguments) {
        SootCommandLineArguments parser = null;
        try {
            parser = new SootCommandLineArguments();
            parser.parse(arguments);
        } catch (ParseException e) {
            System.out.print(e.toString() + "\n");
            parser.printHelp();
            System.exit(-1);
        }
        return parser;
    }

    String getClassPathFile() {
        return getRequiredArgument(CLASSPATH_FILE_PARAMETER_NAME);
    }

    String getReachableMethodsFilePath() {
        return getRequiredArgument(REACHABLE_METHODS_FILEPATH_PARAMETER_NAME);
    }

    String getFirstPartyDirectory() {
        return getRequiredArgument(FIRST_PARTY_DIRECTORY);
    }

    Optional<String> getCallGraphFilePath() {
        if (commandLine.hasOption(CALL_GRAPH_FILEPATH_PARAMETER_NAME)) {
            return Optional.of(commandLine.getOptionValue(CALL_GRAPH_FILEPATH_PARAMETER_NAME));
        }

        return Optional.empty();
    }

    private String getRequiredArgument(String argumentName) {
        String argValue = commandLine.getOptionValue(argumentName);
        if (argValue == null) {
            throw new IllegalArgumentException("Argument " + argumentName + " missing");
        }
        return argValue;
    }

    private void parse(final String[] args) throws ParseException {
        options.addOption(CLASSPATH_FILE_PARAMETER_NAME, true,
                "The path to the file that contain the classpath used by Soot (REQUIRED)");
        options.addOption(FIRST_PARTY_DIRECTORY, true,
                "The path to the directory which stores first-party code (REQUIRED)");
        options.addOption(REACHABLE_METHODS_FILEPATH_PARAMETER_NAME, true,
                "The path to the file where the reachable methods will be written (REQUIRED)");
        options.addOption(CALL_GRAPH_FILEPATH_PARAMETER_NAME, true,
                "The path to the file where the call graph will be written (OPTIONAL)");

        parseOptions(args);
    }

    private void parseOptions(final String[] args) throws ParseException {
        commandLine = parser.parse(options, args);
    }

    private void printHelp() {
        final HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "Soot", options);
    }
}