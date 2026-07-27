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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

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

        exportCrossReferences(new File(outFile.getAbsolutePath() + ".xrefs"));
    }

    /**
     * Export cross-references as tab-separated records.
     *
     * This is the bridge between a lead and the code behind it: an analyst who
     * finds an interesting string immediately asks which function references
     * it. Without this the agent can only keep searching strings, because
     * strings are the only thing it can search.
     *
     *   STRING <addr> <text>  <referencing functions>
     *   FUNC   <addr> <name>  <calling functions>
     */
    private void exportCrossReferences(File xrefFile) throws Exception {
        ReferenceManager refs = currentProgram.getReferenceManager();
        PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(xrefFile)));

        int strings = 0;
        int functions = 0;

        try {
            writer.println("# type\taddress\tname\treferenced_by");

            DataIterator data = currentProgram.getListing().getDefinedData(true);
            while (data.hasNext() && !monitor.isCancelled()) {
                Data item = data.next();
                Object value = item.getValue();
                if (!(value instanceof String)) {
                    continue;
                }

                String callers = callersOf(refs, item.getAddress());
                if (callers.isEmpty()) {
                    continue;   // unreferenced string: no navigational value
                }

                writer.println("STRING\t0x" + item.getAddress() + "\t"
                        + escape((String) value) + "\t" + callers);
                strings++;
            }

            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext() && !monitor.isCancelled()) {
                Function function = funcs.next();
                String callers = callersOf(refs, function.getEntryPoint());
                if (callers.isEmpty()) {
                    continue;
                }

                writer.println("FUNC\t0x" + function.getEntryPoint() + "\t"
                        + escape(function.getName()) + "\t" + callers);
                functions++;
            }
        } finally {
            writer.close();
        }

        println("ExportDecompiledC: xrefs strings=" + strings + " functions=" + functions
                + " -> " + xrefFile.getAbsolutePath());
    }

    /** Comma-separated "name@0xaddr" for every function referencing target. */
    private String callersOf(ReferenceManager refs, Address target) {
        Set<String> callers = new LinkedHashSet<>();
        ReferenceIterator it = refs.getReferencesTo(target);

        while (it.hasNext()) {
            Reference reference = it.next();
            Function from = getFunctionContaining(reference.getFromAddress());
            if (from != null) {
                callers.add(from.getName() + "@0x" + from.getEntryPoint());
            }
        }

        return String.join(",", callers);
    }

    /** Keep records on a single tab-delimited line. */
    private String escape(String text) {
        return text.replace("\\", "\\\\")
                   .replace("\t", "\\t")
                   .replace("\r", "\\r")
                   .replace("\n", "\\n");
    }
}
