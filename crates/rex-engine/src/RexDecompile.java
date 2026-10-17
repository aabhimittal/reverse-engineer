// Decompile functions for rex (`rex decompile`). Run by analyzeHeadless as a post-script.
//
// Arguments: <output.json> <rex image base, hex> <seconds per function> (<address, hex>... | all)
//
// rex addresses are the file's own virtual addresses. Ghidra may load the image elsewhere (PIE
// ELF files go to 0x100000), so addresses are shifted by Ghidra's image base minus rex's.
//@category rex
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

public class RexDecompile extends GhidraScript {
    /** `all` decompiles at most this many functions. */
    private static final int MAX_ALL = 500;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4) {
            throw new IllegalArgumentException("usage: out.json imagebase seconds (addr...|all)");
        }
        long rexBase = Long.parseUnsignedLong(args[1], 16);
        int seconds = Integer.parseInt(args[2]);
        long delta = currentProgram.getImageBase().getOffset() - rexBase;

        List<Function> funcs = new ArrayList<>();
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        if (args[3].equals("all")) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isThunk() || f.isExternal()) {
                    continue;
                }
                funcs.add(f);
                if (funcs.size() >= MAX_ALL) {
                    break;
                }
            }
        } else {
            for (int i = 3; i < args.length; i++) {
                long a = Long.parseUnsignedLong(args[i], 16);
                Address addr = toAddr(a + delta);
                Function f = getFunctionAt(addr);
                if (f == null) {
                    f = createFunction(addr, null);
                }
                if (f != null) {
                    funcs.add(f);
                } else {
                    first = entry(out, first, "", a, null, "no function at this address");
                }
            }
        }

        DecompInterface ifc = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        ifc.setOptions(options);
        ifc.toggleCCode(true);
        ifc.openProgram(currentProgram);
        try {
            for (Function f : funcs) {
                if (monitor.isCancelled()) {
                    break;
                }
                long rexAddr = f.getEntryPoint().getOffset() - delta;
                DecompileResults r = ifc.decompileFunction(f, seconds, monitor);
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    first = entry(out, first, f.getName(), rexAddr,
                        r.getDecompiledFunction().getC(), null);
                } else {
                    String why = r == null ? "no result"
                        : r.isTimedOut() ? "timed out" : r.getErrorMessage();
                    first = entry(out, first, f.getName(), rexAddr, null, why);
                }
            }
        } finally {
            ifc.dispose();
        }
        out.append("]");
        try (Writer w = new FileWriter(args[0])) {
            w.write(out.toString());
        }
    }

    private static boolean entry(StringBuilder out, boolean first, String name, long addr,
            String c, String error) {
        if (!first) {
            out.append(",");
        }
        out.append("{\"name\":").append(json(name))
            .append(",\"entry\":").append(Long.toUnsignedString(addr))
            .append(",\"c\":").append(json(c))
            .append(",\"error\":").append(json(error))
            .append("}");
        return false;
    }

    private static String json(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        b.append(String.format("\\u%04x", (int) ch));
                    } else {
                        b.append(ch);
                    }
            }
        }
        return b.append("\"").toString();
    }
}
