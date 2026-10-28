import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Decompile selected classes of an APK with the JADX engine bundled in
 * jadx-headless-mcp so the shipped code can be read as Java.
 *
 * Usage: java -cp jadx-headless-mcp-0.7.1-all.jar:classes DecompileApk <apk> <outDir> <prefix>...
 * A class matches when its fully qualified name starts with any prefix.
 */
public final class DecompileApk {
    public static void main(String[] argv) throws Exception {
        if (argv.length < 3) {
            System.err.println("usage: DecompileApk <apk> <outDir> <prefix>...");
            System.exit(2);
        }
        File apk = new File(argv[0]);
        File outDir = new File(argv[1]);
        List<String> prefixes = new ArrayList<>();
        for (int i = 2; i < argv.length; i++) prefixes.add(argv[i]);

        JadxArgs args = new JadxArgs();
        args.setInputFile(apk);
        args.setOutDir(outDir);
        args.setSkipResources(true);
        args.setShowInconsistentCode(false);
        args.setDecompilationMode(jadx.api.DecompilationMode.FALLBACK);
        args.setThreadsCount(Math.max(2, Runtime.getRuntime().availableProcessors() - 1));

        JadxDecompiler decompiler = new JadxDecompiler(args);
        decompiler.load();

        List<JavaClass> selected = new ArrayList<>();
        for (JavaClass cls : decompiler.getClasses()) {
            String name = cls.getFullName();
            for (String p : prefixes) {
                if (name.startsWith(p)) {
                    selected.add(cls);
                    break;
                }
            }
        }
        selected.sort(Comparator.comparing(JavaClass::getFullName));
        System.out.println("selected " + selected.size() + " classes");

        for (JavaClass cls : selected) {
            String code;
            try {
                code = cls.getCode();
            } catch (Throwable t) {
                code = "// decompile failed: " + t;
            }
            File f = new File(outDir, cls.getFullName().replace('.', '/') + ".java");
            File parent = f.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new java.io.IOException("cannot create " + parent);
            }
            try (PrintWriter w = new PrintWriter(f, StandardCharsets.UTF_8)) {
                w.println("// JADX decompilation of " + cls.getFullName() + " from " + apk.getName());
                w.println("// deobfuscated raw name: " + cls.getRawName());
                w.print(code);
            }
        }
        decompiler.close();
        System.out.println("done");
    }
}
