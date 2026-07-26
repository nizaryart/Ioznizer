/* Export decompiled pseudo-C for every function in the loaded program.
 *
 * Invoked by backend/decompiler.py through analyzeHeadless -postScript.
 * Written as a GhidraScript (Java) rather than PyGhidra so it runs on any
 * Ghidra install without requiring the Python bridge to be configured.
 *
 * Args: <output_file> [max_functions] [timeout_seconds]
 *
 * @category Analysis
 */

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecompiledC extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ExportDecompiledC: missing output file argument");
            return;
        }

        File outFile = new File(args[0]);
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 0;
        int timeoutSeconds = args.length > 2 ? Integer.parseInt(args[2]) : 60;

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());

        if (!decompiler.openProgram(currentProgram)) {
            println("ExportDecompiledC: failed to open program: "
                    + decompiler.getLastMessage());
            return;
        }

        PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(outFile)));
        int exported = 0;
        int failed = 0;

        try {
            writer.println("// Decompiled by Ghidra " + ghidra.framework.Application
                    .getApplicationVersion());
            writer.println("// Program: " + currentProgram.getName());
            writer.println("// Language: " + currentProgram.getLanguageID());
            writer.println();

            FunctionIterator functions =
                    currentProgram.getFunctionManager().getFunctions(true);

            while (functions.hasNext() && !monitor.isCancelled()) {
                if (maxFunctions > 0 && exported + failed >= maxFunctions) {
                    break;
                }

                Function function = functions.next();

                // Markers are parsed by backend/decompiler.py to slice the file
                // into individual functions for the decompile_function tool.
                writer.println("// ===== FUNCTION " + function.getName()
                        + " @ 0x" + function.getEntryPoint() + " =====");

                DecompileResults results =
                        decompiler.decompileFunction(function, timeoutSeconds, monitor);

                if (results != null && results.decompileCompleted()
                        && results.getDecompiledFunction() != null) {
                    writer.println(results.getDecompiledFunction().getC());
                    exported++;
                } else {
                    String reason = (results != null && results.getErrorMessage() != null)
                            ? results.getErrorMessage().trim()
                            : "decompiler returned no result";
                    writer.println("// [decompilation failed] " + reason);
                    failed++;
                }
                writer.println();
            }
        } finally {
            writer.close();
            decompiler.dispose();
        }

        println("ExportDecompiledC: exported=" + exported + " failed=" + failed
                + " -> " + outFile.getAbsolutePath());
    }
}
