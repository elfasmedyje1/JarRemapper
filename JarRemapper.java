import org.objectweb.asm.*;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.jar.*;
import java.util.regex.Pattern;

public class JarRemapper {

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Configuration / static fields ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    static Scanner STDIN = new Scanner(System.in);
    static boolean VERBOSE   = false;
    static boolean DECRYPT   = false;
    static boolean DECOMPILE = false;
    static boolean INTERACTIVE = false;
    static boolean DRY_RUN   = false;
    static String  LIBS_DIR  = null;
    static String  SRG_FILE  = null;
    static String  TINY_FILE = null;
    static int     MIN_LEN   = 3;
    static int     MAX_LEN   = 64;
    static double  MIN_SCORE = 0.55;
    static String  OUT_JAR   = null;
    static String  OUT_MAP   = null;
    static String  STRINGS_FILE = null;

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Scoring policy constants ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Anchor scores are multiplied by these weights depending on how class-specific
    // the evidence is. Higher weight = stronger preference when picking a class name.
    /** Runtime-decrypted strings (ENI external input) are bound to one class ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â boost them. */
    static final double WEIGHT_EXTERNAL          = 1.3;
    /** Unattributed all_strings.txt fallback: only wins when a class has no other anchor. */
    static final double WEIGHT_UNATTRIBUTED      = 0.5;
    /** A string the developer wrote to identify the class: enum constant name, Logger name,
     *  Class.forName target, or a value read from a known string-table. */
    static final double WEIGHT_IDENTITY_STRING   = 1.5;
    /** Below this adjusted (frequency-penalised) score an anchor carries too little signal. */
    static final double ANCHOR_MIN_ADJUSTED      = 0.08;
    /** Frequency at/below which the gentler sqrt penalty applies; above it, linear penalty. */
    static final int    FREQ_SQRT_THRESHOLD      = 5;
    /** Penalty multiplier for ALL-CAPS / SCREAMING_SNAKE_CASE names (likely constants). */
    static final double ALLCAPS_PENALTY          = 0.65;
    /** Minimum vowel ratio for short strings ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â rejects ciphertext / consonant runs. */
    static final double MIN_VOWEL_RATIO          = 0.20;
    /** Strings shorter than this skip the vowel-ratio gate (paths dilute vowels naturally). */
    static final int    VOWEL_RATIO_MAX_LEN      = 12;
    /** Per-class cap on generic call-site method renames ("init"/"setup") before they add noise. */
    static final int    CALLSITE_RENAME_CAP      = 3;

    static Set<String> libraryClasses = new HashSet<>();

    // Package prefixes that are bundled vendor/library code ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â never rename these.
    static final List<String> LIBRARY_PACKAGE_PREFIXES = Arrays.asList(
            "org.lwjgl.",
            "org.spongepowered.asm.",
            "org.spongepowered.tools.",
            "net.fabricmc.",
            "net.minecraftforge.",
            "cpw.mods.",
            "com.google.",
            "com.mojang.",
            "io.netty.",
            "org.apache.",
            "org.slf4j.",
            "org.objectweb.asm.",
            "net.minecrell.",
            "me.shedaniel.",
            "dev.isxander."
    );

    static boolean isLibraryClass(String dotName) {
        if (libraryClasses.contains(dotName)) return true;
        for (String prefix : LIBRARY_PACKAGE_PREFIXES)
            if (dotName.startsWith(prefix)) return true;
        return false;
    }

    static final Pattern URL_PATTERN  = Pattern.compile("https?://[\\w./\\-?=&%#@:]+");
    static final Pattern IDENTIFIER   = Pattern.compile("[A-Za-z][A-Za-z0-9_\\- ]{2,63}");
    static final Pattern PATH_PATTERN = Pattern.compile("[a-zA-Z0-9_\\-]+[/\\\\][a-zA-Z0-9_\\-./\\\\]+");

    // Method-descriptor shapes for the varargs-dispatcher check. Pre-compiled because they are
    // tested against every method of every class in Pass 6 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â String.matches() would otherwise
    // recompile the Pattern on each call.
    /** Full descriptor of a single reference-array-arg void method, e.g. "([Lfoo/Bar;)V". */
    static final Pattern ARRAY_VARARG_DESCRIPTOR = Pattern.compile("\\(\\[L[^;]+;\\)V");
    /** Just the argument portion: a single reference array type, e.g. "[Lfoo/Bar;". */
    static final Pattern ARRAY_VARARG_ARGS = Pattern.compile("\\[L[^;]+;");

    // String-anchor reject patterns. scoreString() runs once per candidate string (every LDC,
    // field constant and external string), so these are pre-compiled rather than recompiled
    // per call via String.matches().
    /** Slash-separated internal class name, e.g. "net/minecraft/Foo". */
    static final Pattern SLASH_PATH       = Pattern.compile("[A-Za-z0-9_$/]+(?:/[A-Za-z0-9_$/]+)+");
    /** Version string, e.g. "1.8.0_202" or "21.0.3". */
    static final Pattern VERSION_STRING   = Pattern.compile("[0-9]+\\.[0-9]+[._][0-9].*");
    /** Lowercase fully-qualified class name with 3+ segments, e.g. "net.minecraft.client.Minecraft". */
    static final Pattern LOWER_FQCN       = Pattern.compile("[a-z][a-z0-9_$]*(\\.[a-z][a-z0-9_$]*){2,}.*");
    /** Bare HTTP header name, e.g. "Content-Type", "X-Forwarded-For". */
    static final Pattern HTTP_HEADER_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z][A-Za-z0-9]*)+");

    static final Set<String> NOISE_WORDS = new HashSet<>(Arrays.asList(
            // Java keywords and literals
            "true", "false", "null", "this", "super", "void", "class", "return",
            "static", "final", "public", "private", "protected", "abstract",
            // Charset names ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â appear everywhere, make terrible class names
            "utf-8", "utf8", "iso-8859-1", "utf-16", "ascii", "us-ascii",
            // Root package names ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â too generic
            "java", "javax", "com", "org", "net", "io",
            // JDK type names that score high but rename everything to the same thing
            "string", "object", "integer", "boolean", "long", "double", "float",
            "byte", "short", "character", "number", "enum", "record",
            "exception", "error", "throwable", "runtimeexception",
            "list", "map", "set", "queue", "collection", "iterator",
            "arraylist", "hashmap", "hashset", "linkedlist",
            "optional", "stream", "future", "thread", "runnable",
            // Very common single-word nouns that obfuscators leave in string pools
            "type", "value", "result", "data", "info", "item", "entry",
            "builder", "handler", "listener", "callback", "provider",
            "factory", "registry", "config", "settings", "options",
            "client", "server", "request", "response", "message",
            "event", "action", "task", "worker", "service",
            "node", "element", "field", "method", "param",
            // Logging noise ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â including severity levels not already listed
            "logger", "log", "debug", "info", "warn", "warning", "error", "trace", "fatal", "severe",
            // Common obfuscator-preserved strings
            "enabled", "disabled", "none", "success", "failed", "unknown", "default",
            // Crypto noise (base64 alphabet strings handled separately in scoreString)
            "aes", "des", "cbc", "ecb", "nopadding", "pkcs5padding",
            // Minecraft / game-engine specific ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â appear in dozens of classes
            "world", "level", "player", "entity", "block", "chunk", "item", "inventory",
            "packet", "update", "render", "tick", "game",
            // Architectural patterns ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â too generic as class names
            "manager", "controller", "processor", "executor", "dispatcher",
            // Sentence fragments that score high (all-letters, uppercase-first)
            "invalid", "cannot", "unable", "already",
            // JVM bytecode attribute names ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â appear in any jar bundling a bytecode library
            // (javassist, ASM, BCEL). These are JVM spec constants, never good class names.
            "linenumbertable", "localvariabletable", "localvariabletypetable",
            "bootstrapmethods", "stackmaptable", "stackmap", "nesthost", "nestmembers",
            "annotationdefault", "sourcefile", "methodparameters", "exceptions", "deprecated",
            "innerclasses", "enclosingmethod", "signature", "constantvalue", "synthetic",
            "runtimevisibleannotations", "runtimeinvisibleannotations"
    ));

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Entry point / CLI parsing ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    public static void main(String[] args) throws Exception {
        if (args.length < 1) { printUsage(); return; }

        List<String> positional = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-v":         VERBOSE      = true;                          break;
                case "-decrypt":   DECRYPT      = true;                          break;
                case "-decompile": DECOMPILE    = true;                          break;
                case "-i":         INTERACTIVE  = true;                          break;
                case "-dry":       DRY_RUN      = true;                          break;
                case "-libs":      LIBS_DIR     = args[++i];                     break;
                case "-srg":       SRG_FILE     = args[++i];                     break;
                case "-tiny":      TINY_FILE    = args[++i];                     break;
                case "-minlen":    MIN_LEN      = Integer.parseInt(args[++i]);   break;
                case "-maxlen":    MAX_LEN      = Integer.parseInt(args[++i]);   break;
                case "-score":     MIN_SCORE    = Double.parseDouble(args[++i]); break;
                case "-out":       OUT_JAR      = args[++i];                     break;
                case "-map":       OUT_MAP      = args[++i];                     break;
                case "-strings":   STRINGS_FILE = args[++i];                     break;
                default:           positional.add(args[i]);                       break;
            }
        }

        if (positional.isEmpty()) { printUsage(); return; }

        File inputJar = new File(positional.get(0)).getAbsoluteFile();
        if (!inputJar.exists()) {
            System.err.println("[-] JAR not found: " + inputJar);
            return;
        }

        String baseName = inputJar.getName().replaceAll("(?i)\\.jar$", "");
        File outputJar = OUT_JAR != null ? new File(OUT_JAR)
                : new File(inputJar.getParentFile(), baseName + "_remapped.jar");
        File mapFile = OUT_MAP != null ? new File(OUT_MAP)
                : new File(inputJar.getParentFile(), baseName + "_mapping.txt");

        System.out.println("[*] Input    : " + inputJar);
        System.out.println("[*] Output   : " + outputJar);
        System.out.println("[*] Mapping  : " + mapFile);
        if (STRINGS_FILE != null) System.out.println("[*] Strings  : " + STRINGS_FILE);
        if (LIBS_DIR != null)     System.out.println("[*] Libs     : " + LIBS_DIR);
        if (SRG_FILE != null)     System.out.println("[*] SRG Map  : " + SRG_FILE);
        if (TINY_FILE != null)    System.out.println("[*] Tiny Map : " + TINY_FILE);
        if (DECRYPT)     System.out.println("[*] Decrypt     : ENABLED (Caution: executes <clinit>)");
        if (DECOMPILE)   System.out.println("[*] Decompile   : ENABLED");
        if (INTERACTIVE) System.out.println("[*] Interactive : ENABLED");
        if (DRY_RUN)     System.out.println("[*] DRY RUN     : no files will be written");
        System.out.println();

        if (LIBS_DIR != null) {
            loadLibraryClasses(new File(LIBS_DIR));
            System.out.println("[+] Loaded " + libraryClasses.size() + " classes from libraries.");
        }

        Map<String, byte[]> classes   = new LinkedHashMap<>();
        Map<String, byte[]> resources = new LinkedHashMap<>();

        try (JarFile jar = new JarFile(inputJar)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                byte[] data;
                try (InputStream is = jar.getInputStream(entry)) { data = readAllBytes(is); }
                if (entry.getName().endsWith(".class")) {
                    String name = trueClassName(data, entry.getName());
                    classes.put(name, data);
                } else if (!entry.isDirectory()) {
                    resources.put(entry.getName(), data);
                }
            }
        }

        System.out.println("[+] Loaded " + classes.size() + " classes, " + resources.size() + " resources.");

        // Optional: load pre-decrypted strings from ENI_StringDumper output
        Map<String, List<String>> externalStrings = new HashMap<>();
        if (STRINGS_FILE != null) {
            externalStrings = loadExternalStrings(new File(STRINGS_FILE));
            List<String> unattributed = externalStrings.remove("");
            if (unattributed != null) {
                System.out.println("[!] " + unattributed.size()
                        + " strings in -strings file have no class attribution (format-b / all_strings.txt)."
                        + " Use per-package .log files from ENI_StringDumper for best results.");
                // Store under sentinel key "\0" so extractAnchors can broadcast them
                // at reduced weight (score * 0.5) as a last-resort fallback.
                externalStrings.put("\0", unattributed);
            }
            System.out.println("[+] Loaded external strings for " + externalStrings.size() + " classes.");
        }

        if (DECRYPT) {
            int before = externalStrings.size();
            decryptInline(classes, externalStrings);
            System.out.println("[+] Inline decryption added strings for " + (externalStrings.size() - before) + " classes.");
        }

        System.out.println("[*] Scanning class metadata...");
        Map<String, ClassMeta> metaMap = scanMetadata(classes);

        System.out.println("[*] Extracting string anchors and building call graph...");
        Map<String, Set<String>> callers = new HashMap<>();
        Map<String, List<StringAnchor>> anchors = extractAnchors(classes, externalStrings, callers, metaMap);
        System.out.println("[+] Found anchors in " + anchors.size() + " classes.");

        System.out.println("[*] Building rename map...");
        Map<String, Rename> classRenames  = new LinkedHashMap<>();
        Map<String, Rename> fieldRenames  = new LinkedHashMap<>();
        Map<String, Rename> methodRenames = new LinkedHashMap<>();
        Map<String, String> fieldDescriptors = new HashMap<>();
        buildRenameMap(classes, anchors, metaMap, classRenames, fieldRenames, methodRenames, callers, fieldDescriptors);
        System.out.println("[+] " + classRenames.size() + " classes, "
                + fieldRenames.size() + " fields, "
                + methodRenames.size() + " methods to rename.");

        if (classRenames.isEmpty() && fieldRenames.isEmpty() && methodRenames.isEmpty()) {
            System.out.println("[!] Nothing to rename.");
            return;
        }

        // Build superMap for proper getCommonSuperClass resolution
        Map<String, String> superMap = new HashMap<>();
        for (Map.Entry<String, ClassMeta> e : metaMap.entrySet()) {
            String superDot = e.getValue().superName;
            if (superDot == null || superDot.equals("java.lang.Object")) continue;
            Rename r  = classRenames.get(e.getKey());
            Rename sr = classRenames.get(superDot);
            String newInternal   = r  != null ? internal(r.name)  : internal(e.getKey());
            String superInternal = sr != null ? internal(sr.name) : internal(superDot);
            superMap.put(newInternal, superInternal);
        }

        if (!DRY_RUN) {
            System.out.println("[*] Applying renames and writing output JAR...");
            writeRemappedJar(classes, resources, classRenames, fieldRenames, methodRenames, outputJar, superMap);
            writeMappingFile(classRenames, fieldRenames, methodRenames, mapFile, inputJar);

            if (SRG_FILE != null) {
                writeSrgMapping(classRenames, fieldRenames, methodRenames, new File(SRG_FILE));
            }
            if (TINY_FILE != null) {
                writeTinyMapping(classRenames, fieldRenames, methodRenames, fieldDescriptors, new File(TINY_FILE));
            }

            if (DECOMPILE) {
                runDecompiler(outputJar);
            }
        } else {
            System.out.println("[*] Dry run complete ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no files written.");
        }

        long[] classCounts  = countByConf(classRenames.values());
        long[] fieldCounts  = countByConf(fieldRenames.values());
        long[] methodCounts = countByConf(methodRenames.values());

        System.out.println();
        System.out.println("  Done.");
        System.out.printf("  Classes renamed:       %d  (HIGH: %d  MEDIUM: %d  LOW: %d)%n",
                classRenames.size(),  classCounts[0], classCounts[1], classCounts[2]);
        System.out.printf("  Fields renamed:        %d  (HIGH: %d  MEDIUM: %d  LOW: %d)%n",
                fieldRenames.size(),  fieldCounts[0], fieldCounts[1], fieldCounts[2]);
        System.out.printf("  Methods renamed:       %d  (HIGH: %d  MEDIUM: %d  LOW: %d)%n",
                methodRenames.size(), methodCounts[0], methodCounts[1], methodCounts[2]);
        if (!DRY_RUN) {
            System.out.println("  Output JAR : " + outputJar.getAbsolutePath());
            System.out.println("  Mapping    : " + mapFile.getAbsolutePath());
        }
    }

    static long[] countByConf(Collection<Rename> renames) {
        long high = 0, med = 0, low = 0;
        for (Rename r : renames) {
            if (r.confidence == Confidence.HIGH)        high++;
            else if (r.confidence == Confidence.MEDIUM) med++;
            else                                        low++;
        }
        return new long[]{high, med, low};
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Metadata scanning ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Superclass, interfaces, mixin targets, inner classes.

    static class ClassMeta {
        String superName;
        List<String> interfaces = new ArrayList<>();
        String mixinTarget;
        boolean isInnerClass;
        String outerClass;
        int methodCount;
        int fieldCount;
        int doubleFieldCount;
        boolean hasPrivateCtor;
        boolean hasStaticInstance;
        boolean allStaticMethods = true;
        // Structural type flags
        boolean isInterface;
        boolean isEnum;
        boolean isAnnotation;
        int abstractMethodCount;
        boolean abstractMethodsReturnVoid = true; // for Consumer/Function interface classification
        // @Shadow-annotated members carry exact original Minecraft names ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â highest confidence
        Map<String, String> shadowFields  = new LinkedHashMap<>(); // obfuscated name -> shadow name
        Map<String, String> shadowMethods = new LinkedHashMap<>(); // obfuscated name+desc -> shadow name
        // String pool / table detection
        boolean isStringTable = false; // detected as a string pool class (static String[] holder)
    }

    static Map<String, ClassMeta> scanMetadata(Map<String, byte[]> classes) {
        Map<String, ClassMeta> result = new HashMap<>();

        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            ClassMeta meta = new ClassMeta();
            // Local mutable flag for string-array field detection (captured in inner class)
            boolean[] hasStaticStringArray = { false };
            try {
                new ClassReader(e.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    String internalName;

                    @Override
                    public void visit(int version, int access, String name, String sig,
                                      String superName, String[] interfaces) {
                        this.internalName = name;
                        meta.superName = superName != null ? binary(superName) : null;
                        if (interfaces != null)
                            for (String iface : interfaces)
                                meta.interfaces.add(binary(iface));
                        meta.isInterface  = (access & Opcodes.ACC_INTERFACE)  != 0;
                        meta.isEnum       = (access & Opcodes.ACC_ENUM)       != 0;
                        meta.isAnnotation = (access & Opcodes.ACC_ANNOTATION) != 0;
                    }

                    @Override
                    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                        // Detect @Mixin(value = SomeClass.class)
                        if (descriptor.equals("Lorg/spongepowered/asm/mixin/Mixin;")) {
                            return new AnnotationVisitor(Opcodes.ASM9) {
                                @Override
                                public void visit(String name, Object value) {
                                    if (value instanceof org.objectweb.asm.Type)
                                        meta.mixinTarget = ((org.objectweb.asm.Type) value)
                                                .getClassName();
                                }
                                @Override
                                public AnnotationVisitor visitArray(String name) {
                                    return new AnnotationVisitor(Opcodes.ASM9) {
                                        @Override
                                        public void visit(String n, Object value) {
                                            if (meta.mixinTarget == null && value instanceof org.objectweb.asm.Type)
                                                meta.mixinTarget = ((org.objectweb.asm.Type) value)
                                                        .getClassName();
                                        }
                                    };
                                }
                            };
                        }
                        return null;
                    }

                    @Override
                    public void visitOuterClass(String owner, String name, String descriptor) {
                        meta.isInnerClass = true;
                        meta.outerClass = binary(owner);
                    }

                    @Override
                    public void visitInnerClass(String name, String outerName,
                                                 String innerName, int access) {
                        String dotName = binary(name);
                        if (dotName.equals(e.getKey()) && outerName != null) {
                            meta.isInnerClass = true;
                            meta.outerClass = binary(outerName);
                        }
                    }

                    @Override
                    public FieldVisitor visitField(int access, String name, String descriptor,
                                                    String signature, Object value) {
                        meta.fieldCount++;
                        if (descriptor.equals("D") || descriptor.equals("F")) meta.doubleFieldCount++;
                        if ((access & Opcodes.ACC_STATIC) != 0 && (access & Opcodes.ACC_FINAL) != 0) {
                            if (descriptor.equals("L" + internalName + ";")) meta.hasStaticInstance = true;
                        }
                        // Detect static String[] field ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â used for string-table class identification
                        if ((access & Opcodes.ACC_STATIC) != 0 && descriptor.equals("[Ljava/lang/String;")) {
                            hasStaticStringArray[0] = true;
                        }
                        // Detect @Shadow annotation ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â carries the original Minecraft field name
                        return new FieldVisitor(Opcodes.ASM9) {
                            @Override
                            public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
                                if (desc.equals("Lorg/spongepowered/asm/mixin/Shadow;")) {
                                    return new AnnotationVisitor(Opcodes.ASM9) {
                                        @Override
                                        public void visit(String aname, Object value) {
                                            // @Shadow(aliases = {"originalName"}) or prefix handling
                                            // The field name itself IS the shadow name when no prefix
                                            // Store: obfuscated field name -> declared name
                                        }
                                        @Override public void visitEnd() {
                                            // Shadow field name = the declared field name (already readable)
                                            // Only record if the field name is already readable (no rename needed)
                                            // or if it differs from the obfuscated name via prefix stripping
                                            meta.shadowFields.put(name, name);
                                        }
                                    };
                                }
                                return null;
                            }
                        };
                    }

                    @Override
                    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                     String signature, String[] exceptions) {
                        if (name.equals("<init>")) {
                            if ((access & Opcodes.ACC_PRIVATE) != 0) meta.hasPrivateCtor = true;
                        } else if (!name.equals("<clinit>")) {
                            meta.methodCount++;
                            if ((access & Opcodes.ACC_STATIC) == 0) meta.allStaticMethods = false;
                            if ((access & Opcodes.ACC_ABSTRACT) != 0) meta.abstractMethodCount++;
                            // Track whether abstract methods return void â€” static/default interface
                            // methods must not affect the Consumer vs Function classification (Pass 3).
                            int retStart = descriptor.lastIndexOf(')') + 1;
                            if (retStart > 0 && !descriptor.substring(retStart).equals("V")
                                    && (access & Opcodes.ACC_ABSTRACT) != 0) {
                                meta.abstractMethodsReturnVoid = false;
                            }
                        }

                        return new MethodVisitor(Opcodes.ASM9) {
                            // In the Mixin framework, @Shadow methods that shadow an accessor whose name
                            // begins with a reserved prefix (default "shadow$") have that prefix stripped
                            // to recover the original Minecraft method name. The prefix is configurable
                            // via @Shadow(prefix = "...") and defaults to "shadow$". When isShadow is
                            // true and the declared name starts with shadowPrefix, we strip it before
                            // recording the mapping, giving us the actual target name in Minecraft.
                            boolean isShadow = false;
                            String shadowPrefix = "shadow$";

                            @Override
                            public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
                                if (desc.equals("Lorg/spongepowered/asm/mixin/Shadow;")) {
                                    isShadow = true;
                                    return new AnnotationVisitor(Opcodes.ASM9) {
                                        @Override
                                        public void visit(String aname, Object value) {
                                            if ("prefix".equals(aname) && value instanceof String)
                                                shadowPrefix = (String) value;
                                        }
                                    };
                                }
                                return null;
                            }

                            @Override
                            public void visitEnd() {
                                if (isShadow && !name.equals("<init>") && !name.equals("<clinit>")) {
                                    // Strip shadow prefix to recover original name
                                    String originalName = name.startsWith(shadowPrefix)
                                            ? name.substring(shadowPrefix.length()) : name;
                                    meta.shadowMethods.put(name + descriptor, originalName);
                                }
                            }
                        };
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            } catch (Throwable ignored) {}
            // String-table class: few non-init methods + has a static String[] field.
            // >80% of methods being <clinit>/<init> is implied by methodCount <= 2.
            if (meta.methodCount <= 2 && hasStaticStringArray[0]) {
                meta.isStringTable = true;
            }
            result.put(e.getKey(), meta);
        }
        return result;
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ External string loading ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Load external strings from ENI_StringDumper output.
    // Accepts two formats:
    //   (a) Package .log files:  ClassName.fieldName[index] = "escaped_value"
    //   (b) all_strings.txt:     one raw escaped value per line (no source prefix)
    // In both cases ENI escape sequences (\n, \r, \t, \\, \") are decoded before
    // the string is scored, so high-bytes / special chars don't depress the score.

    static Map<String, List<String>> loadExternalStrings(File f) {
        Map<String, List<String>> result = new HashMap<>();
        if (!f.exists()) return result;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                int eq = line.indexOf(" = \"");
                if (eq >= 0) {
                    // Format (a): source = "escaped_value"
                    String source = line.substring(0, eq).trim();
                    String raw    = line.substring(eq + 4);
                    if (raw.endsWith("\"")) raw = raw.substring(0, raw.length() - 1);
                    String value    = unescapeEni(raw);
                    String className = extractClassName(source);
                    if (className != null && !className.isEmpty())
                        result.computeIfAbsent(className, k -> new ArrayList<>()).add(value);
                } else {
                    // Format (b): raw escaped value only (all_strings.txt)
                    // No class association ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â add to a sentinel key so the caller
                    // can decide what to do with unattributed strings.
                    String value = unescapeEni(line);
                    result.computeIfAbsent("", k -> new ArrayList<>()).add(value);
                }
            }
        } catch (Throwable ignored) {}
        return result;
    }

    /** Decode ENI_StringDumper escape sequences back to the original characters. */
    static String unescapeEni(String s) {
        if (s.indexOf('\\') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case 'n':  sb.append('\n'); i++; break;
                    case 'r':  sb.append('\r'); i++; break;
                    case 't':  sb.append('\t'); i++; break;
                    case '\\': sb.append('\\'); i++; break;
                    case '"':  sb.append('"');  i++; break;
                    default:   sb.append(c);         break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    static String extractClassName(String source) {
        // Strip array indices like [0] and method call notation like [ldc:methodName],
        // [bsm:method], [strtable:...], [classref:...], [indy:...] ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â all ENI bracket formats.
        source = source.replaceAll("\\[.*", "");
        // Strip method call parens like "methodName()"
        source = source.replaceAll("\\(\\)", "");
        // Remove any trailing dot left after stripping "[ldc:...]" from "Class.[ldc:method]"
        while (source.endsWith(".")) source = source.substring(0, source.length() - 1);
        // After stripping brackets, "com.example.Foo" is a fully-qualified class name.
        // We return it directly if it contains at least one dot (has a package), without
        // stripping the last segment ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â that mistake would return the package instead of the class.
        // Only strip the last segment when the source was "Class.fieldName" format
        // (no bracket was present, indicated by the original containing no ".[" pattern).
        int lastDot = source.lastIndexOf('.');
        if (lastDot <= 0) return null;
        // Heuristic: if the last segment starts with a lowercase letter it is a field/method name,
        // not a class name ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â strip it. If it starts uppercase it IS the class name, return as-is.
        String lastSegment = source.substring(lastDot + 1);
        if (lastSegment.isEmpty()) return null;
        if (Character.isUpperCase(lastSegment.charAt(0))) return source; // "com.example.Foo" ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ return whole thing
        return source.substring(0, lastDot); // "com.example.Foo.fieldName" ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ "com.example.Foo"
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Anchor extraction ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Static bytecode scan + external strings to build per-class string anchors.

    static Map<String, List<StringAnchor>> extractAnchors(Map<String, byte[]> classes,
                                                            Map<String, List<String>> external,
                                                            Map<String, Set<String>> callers,
                                                            Map<String, ClassMeta> metaMap) {
        Map<String, List<StringAnchor>> result = new LinkedHashMap<>();

        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            String className = e.getKey();
            List<StringAnchor> anchors = new ArrayList<>();
            // Flags for post-scan boosts (must be effectively-final array for inner class capture)
            boolean[] accessesStringTable = { false }; // set if GETSTATIC on a known string-table field

            // Inject external (runtime-decrypted) strings first ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â highest priority
            List<String> extStrings = external.get(className);
            if (extStrings != null) {
                for (String s : extStrings) {
                    double score = scoreString(s);
                    if (score > 0)
                        anchors.add(new StringAnchor(null, s, score * WEIGHT_EXTERNAL, AnchorType.EXTERNAL));
                }
            }
            // Unattributed strings (all_strings.txt format-b) are stored under "\0".
            // Add them as low-priority fallback anchors (score * WEIGHT_UNATTRIBUTED) so they only
            // win when a class has no class-specific evidence at all.
            List<String> unattributed = external.get("\0");
            if (unattributed != null && extStrings == null) {
                for (String s : unattributed) {
                    double score = scoreString(s);
                    if (score > 0)
                        anchors.add(new StringAnchor(null, s, score * WEIGHT_UNATTRIBUTED, AnchorType.EXTERNAL));
                }
            }

            // Determine if this class itself is an enum (for Change C)
            ClassMeta clsMeta = metaMap.get(className);
            boolean isEnumClass = clsMeta != null && clsMeta.isEnum;
            // Internal name form (slashes) used for descriptor matching
            String classInternal = internal(className);

            // Static bytecode scan
            try {
                new ClassReader(e.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public FieldVisitor visitField(int access, String name, String descriptor,
                                                    String signature, Object value) {
                        if (value instanceof String) {
                            String s = (String) value;
                            anchors.add(new StringAnchor(name, s, scoreString(s), AnchorType.FIELD_CONST));
                        }
                        return null;
                    }

                    @Override
                    public MethodVisitor visitMethod(int access, String mname, String descriptor,
                                                     String signature, String[] exceptions) {
                        String currentMethod = className + "." + mname + descriptor;
                        // Is this the enum <clinit>? Used for Change C.
                        boolean isEnumClinit = isEnumClass && mname.equals("<clinit>");

                        // Tracks the last String constant on the stack so we can associate it with
                        // the field it's stored into. State:
                        //   lastLdc   ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the most recent String LDC (or null if the stack is dirty)
                        //   lastField ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the field name from the preceding PUTFIELD/PUTSTATIC
                        //   locals    ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â maps local variable slot -> String value for ASTORE/ALOAD tracking
                        return new MethodVisitor(Opcodes.ASM9) {
                            String lastField = null;
                            String lastLdc   = null;
                            Map<Integer, String> locals = new HashMap<>();

                            @Override
                            public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                                if ((opcode == Opcodes.PUTSTATIC || opcode == Opcodes.PUTFIELD) && lastLdc != null) {
                                    // Change C: enum constant field stores ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the LDC is the original enum
                                    // constant name. Detected by: PUTSTATIC of the class's own type in <clinit>.
                                    if (isEnumClinit && opcode == Opcodes.PUTSTATIC
                                            && fdesc.equals("L" + classInternal + ";")
                                            && owner.equals(classInternal)) {
                                        double enumScore = scoreString(lastLdc);
                                        if (enumScore > 0) {
                                            anchors.add(new StringAnchor(fname, lastLdc,
                                                    enumScore * WEIGHT_IDENTITY_STRING, AnchorType.IDENTIFIER));
                                        }
                                    } else {
                                        anchors.add(new StringAnchor(fname, lastLdc, scoreString(lastLdc), classifyString(lastLdc)));
                                    }
                                }
                                // Change A: track GETSTATIC on a known string-table's String[] field
                                if (opcode == Opcodes.GETSTATIC && fdesc.equals("[Ljava/lang/String;")) {
                                    String ownerDot = binary(owner);
                                    ClassMeta ownerMeta = metaMap.get(ownerDot);
                                    if (ownerMeta != null && ownerMeta.isStringTable) {
                                        accessesStringTable[0] = true;
                                    }
                                }
                                lastField = (opcode == Opcodes.PUTSTATIC || opcode == Opcodes.PUTFIELD)
                                        ? fname : null;
                                lastLdc = null;
                            }

                            @Override
                            public void visitLdcInsn(Object cst) {
                                if (!(cst instanceof String)) { lastField = null; lastLdc = null; return; }
                                String s = (String) cst;
                                anchors.add(new StringAnchor(lastField, s, scoreString(s), classifyString(s)));
                                lastLdc = s;
                                lastField = null;
                            }

                            @Override
                            public void visitInvokeDynamicInsn(String name, String descriptor,
                                                                Handle bsm, Object... bsmArgs) {
                                // Many obfuscators use invokedynamic for string decryption. We can't
                                // execute the BSM statically, but String-typed BSM arguments (e.g.
                                // the encrypted payload or a constant key) are worth scoring as anchors.
                                for (Object arg : bsmArgs) {
                                    if (arg instanceof String) {
                                        String s = (String) arg;
                                        anchors.add(new StringAnchor(null, s, scoreString(s), classifyString(s)));
                                        lastLdc = s;
                                    }
                                }
                                // If this indy call returns String, keep lastLdc live for subsequent ASTORE
                                if (!descriptor.endsWith(")Ljava/lang/String;")) {
                                    lastLdc = null;
                                }
                                lastField = null;
                            }

                            @Override
                            public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                                String target = binary(owner) + "." + name + desc;
                                callers.computeIfAbsent(target, k -> new HashSet<>()).add(currentMethod);

                                // Logger.getLogger(String) / LoggerFactory.getLogger(Class/String) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â
                                // the preceding LDC is typically the class name or a module name, making
                                // it a HIGH-confidence anchor for the enclosing class.
                                if (lastLdc != null) {
                                    boolean isLoggerCall =
                                        (owner.equals("java/util/logging/Logger")          && name.equals("getLogger"))
                                     || (owner.equals("org/slf4j/LoggerFactory")           && name.equals("getLogger"))
                                     || (owner.equals("org/apache/logging/log4j/LogManager") && name.equals("getLogger"))
                                     || (owner.equals("org/apache/commons/logging/LogFactory") && name.equals("getLog"));
                                    // Class.forName(String) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the LDC is a class name used for reflection
                                    boolean isClassForName =
                                        owner.equals("java/lang/Class") && name.equals("forName")
                                        && desc.startsWith("(Ljava/lang/String;)");
                                    if (isLoggerCall || isClassForName) {
                                        double score = scoreString(lastLdc);
                                        if (score > 0)
                                            // Boost: developer wrote this string specifically to identify the class
                                            anchors.add(new StringAnchor(null, lastLdc, score * WEIGHT_IDENTITY_STRING, AnchorType.EXTERNAL));
                                    }
                                }

                                // If this call returns String, whatever was in lastLdc before may now be
                                // the argument to a decrypt(String) call ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â keep it live so a subsequent
                                // ASTORE captures it into locals for the multi-hop chain.
                                // If the call does NOT return String, clear tracking.
                                if (!desc.endsWith(")Ljava/lang/String;")) {
                                    lastLdc = null;
                                }
                                lastField = null;
                            }

                            @Override
                            public void visitVarInsn(int opcode, int var) {
                                if (opcode == Opcodes.ASTORE && lastLdc != null) {
                                    locals.put(var, lastLdc);
                                } else if (opcode == Opcodes.ALOAD) {
                                    lastLdc = locals.get(var);
                                } else {
                                    lastLdc = null;
                                }
                                lastField = null;
                            }

                            @Override
                            public void visitInsn(int opcode) { lastField = null; lastLdc = null; }
                            @Override
                            public void visitTypeInsn(int opcode, String type) { lastField = null; lastLdc = null; }
                        };
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            } catch (Throwable ignored) {}

            // Change A: if this class accesses a known string-table via GETSTATIC,
            // its EXTERNAL anchors are resolved-at-runtime string-table values ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â
            // very class-specific evidence ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â so boost them.
            if (accessesStringTable[0]) {
                for (int i = 0; i < anchors.size(); i++) {
                    StringAnchor a = anchors.get(i);
                    if (a.type == AnchorType.EXTERNAL) {
                        anchors.set(i, new StringAnchor(a.fieldName, a.value, a.score * WEIGHT_IDENTITY_STRING, a.type));
                    }
                }
            }

            if (!anchors.isEmpty())
                result.put(className, anchors);
        }
        return result;
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Rename map construction ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    /** Bundles all the mutable state shared by the rename passes so each pass can be a
     *  separate method instead of an inline block in one giant method. Inputs (classes,
     *  anchors, metaMap, callers) are read-only; the rename maps and bookkeeping sets are
     *  accumulated across passes. */
    static final class RenameContext {
        // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Inputs (read-only) ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        final Map<String, byte[]>              classes;
        final Map<String, List<StringAnchor>>  anchors;
        final Map<String, ClassMeta>           metaMap;
        final Map<String, Set<String>>         callers;
        // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Outputs (accumulated) ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        final Map<String, Rename>  classRenames;
        final Map<String, Rename>  fieldRenames;
        final Map<String, Rename>  methodRenames;
        final Map<String, String>  fieldDescriptors;
        // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Cross-pass bookkeeping ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        final Map<String, Integer> anchorFrequency      = new HashMap<>();
        final Set<String>          usedClassNames       = new HashSet<>();
        final Set<String>          originalClassNames;
        final Map<String, Integer> nameCollisionCounts  = new HashMap<>();
        // Per-owner reserved member signatures so a rename never produces a duplicate
        // name+descriptor (methods) or duplicate name (fields) inside one class.
        final Map<String, Set<String>> reservedMethodSigs = new HashMap<>();
        final Map<String, Set<String>> reservedFieldNames = new HashMap<>();

        RenameContext(Map<String, byte[]> classes, Map<String, List<StringAnchor>> anchors,
                      Map<String, ClassMeta> metaMap, Map<String, Set<String>> callers,
                      Map<String, Rename> classRenames, Map<String, Rename> fieldRenames,
                      Map<String, Rename> methodRenames, Map<String, String> fieldDescriptors) {
            this.classes          = classes;
            this.anchors          = anchors;
            this.metaMap          = metaMap;
            this.callers          = callers;
            this.classRenames     = classRenames;
            this.fieldRenames     = fieldRenames;
            this.methodRenames    = methodRenames;
            this.fieldDescriptors = fieldDescriptors;
            this.originalClassNames = new HashSet<>(classes.keySet());
            // Frequency table across all anchors
            for (List<StringAnchor> list : anchors.values())
                for (StringAnchor a : list)
                    anchorFrequency.merge(a.value, 1, Integer::sum);
        }
    }

    static void buildRenameMap(Map<String, byte[]> classes,
                                Map<String, List<StringAnchor>> anchors,
                                Map<String, ClassMeta> metaMap,
                                Map<String, Rename> classRenames,
                                Map<String, Rename> fieldRenames,
                                Map<String, Rename> methodRenames,
                                Map<String, Set<String>> callers,
                                Map<String, String> fieldDescriptors) {
        RenameContext ctx = new RenameContext(classes, anchors, metaMap, callers,
                classRenames, fieldRenames, methodRenames, fieldDescriptors);

        // Seed reserved member sets with every class's ORIGINAL members so renames can never
        // collide with members we didn't touch; also captures field descriptors for Tiny output.
        collectOriginalMembers(classes, ctx.reservedMethodSigs, ctx.reservedFieldNames, fieldDescriptors);

        // Heuristic passes run in priority order: high-confidence evidence (developer-written
        // @Shadow/@Mixin names) first, then string anchors, then progressively weaker structural
        // and propagation heuristics. Each pass only renames classes/members untouched by earlier ones.
        pass0ShadowMembers(ctx);
        pass1MixinTarget(ctx);
        pass2StringAnchors(ctx);
        pass2bFieldOnly(ctx);
        pass2_5ExceptionSubclass(ctx);
        pass3Structural(ctx);
        pass4Hierarchy(ctx);
        pass5InnerClasses(ctx);
        pass6MethodRename(ctx);

        // Report collisions silently dropped by uniqueName
        int totalCollisions = ctx.nameCollisionCounts.values().stream().mapToInt(Integer::intValue).sum();
        if (totalCollisions > 0) {
            System.out.println("[*] Collisions dropped: " + totalCollisions
                    + " (classes whose anchor matched an existing or already-used name)");
        }

        pass7PackageRename(ctx);
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 6: Method signature and call-site based renaming ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Uses the shape of each method's descriptor (argument and return types) plus call-site
    // context (called from main, clinit, or a constructor) to assign a meaningful method name.
    static void pass6MethodRename(RenameContext ctx) {
        Map<String, byte[]> classes = ctx.classes;
        Map<String, Set<String>> reservedMethodSigs = ctx.reservedMethodSigs;
        Map<String, Rename> methodRenames = ctx.methodRenames;
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            final Set<String> reserved =
                    reservedMethodSigs.computeIfAbsent(cls, k -> new HashSet<>());
            // Per-class cap on call-site "init"/"setup" renames: if many methods in the same
            // class all get the same generic call-site name, it adds noise rather than signal.
            final int[] callsiteInitCount  = {0};
            final int[] callsiteSetupCount = {0};
            try {
                new ClassReader(classEntry.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public MethodVisitor visitMethod(int access, String mname, String descriptor,
                                                     String signature, String[] exceptions) {
                        if (mname.equals("<init>") || mname.equals("<clinit>")) return null;
                        if (isAlreadyReadable(mname)) return null;

                        String key = cls + "." + mname + descriptor;
                        String guessed = guessMethodName(mname, descriptor, access);

                        // Call-site analysis ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â promote methods called from well-known contexts.
                        // Guards:
                        // 1. Only void-returning methods ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â a method returning int/array/object
                        //    can't semantically be an initialiser.
                        // 2. Varargs Object[] dispatchers are excluded even in the call-site path ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â
                        //    these are synthetic dispatchers that get called from everywhere.
                        // 3. Per-class cap of 3 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â when more than 3 methods in the same class would
                        //    receive the same call-site name, the name carries no signal.
                        boolean returnsVoid = descriptor.endsWith(")V");
                        // Varargs dispatchers: single-arg void methods whose only parameter is any
                        // reference array type ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â ([Ljava/lang/Object;)V, ([Lorg/obf/X;)V etc.
                        // These are synthetic trampoline methods generated by obfuscators and carry
                        // no semantic information about what the method does.
                        boolean isArrayVarargs = ARRAY_VARARG_DESCRIPTOR.matcher(descriptor).matches();
                        Set<String> c = ctx.callers.get(key);
                        if (c != null && returnsVoid && !isArrayVarargs) {
                            for (String caller : c) {
                                if (caller.contains(".main([Ljava/lang/String;)V")) {
                                    if (callsiteInitCount[0] < CALLSITE_RENAME_CAP) {
                                        guessed = "init"; callsiteInitCount[0]++;
                                    }
                                    break;
                                }
                                if (caller.contains(".<clinit>()V")) {
                                    if (guessed == null && callsiteSetupCount[0] < CALLSITE_RENAME_CAP) {
                                        guessed = "setup"; callsiteSetupCount[0]++;
                                    }
                                    break;
                                }
                                if (caller.contains(".<init>")) {
                                    if (guessed == null && callsiteInitCount[0] < CALLSITE_RENAME_CAP) {
                                        guessed = "init"; callsiteInitCount[0]++;
                                    }
                                    break;
                                }
                            }
                            // Method called from too many unrelated sites ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â too generic to name
                            if (c.size() > 15 && guessed != null && !guessed.equals("init"))
                                guessed = null;
                        }

                        if (guessed == null) return null;

                        // Decide the final base name first (possibly via prompt),
                        // THEN reserve a collision-free signature for it. Reserving
                        // before the prompt would burn a name the user might skip.
                        String base = guessed;
                        Confidence conf = Confidence.LOW;
                        if (INTERACTIVE) {
                            Rename chosen = promptUser(key, new Rename(guessed, Confidence.LOW), "Method Analysis");
                            if (chosen == null) return null; // user skipped ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â keep original
                            base = chosen.name;
                            conf = chosen.confidence;
                        }

                        // Guarantee the rename cannot collide with another method
                        // of the same descriptor in this class ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â doing so would
                        // emit a duplicate name+descriptor (invalid class).
                        String unique = uniqueMethodName(base, descriptor, reserved);
                        if (unique == null) return null;

                        Rename rename = new Rename(unique, conf);
                        methodRenames.putIfAbsent(key, rename);
                        if (VERBOSE) System.out.println("  METHOD " + mname + " -> " + rename.name
                                + "  (" + descriptor + ")");
                        return null;
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG);
            } catch (Throwable ignored) {}
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 0: @Shadow annotations ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // @Shadow fields/methods in Mixin classes carry the exact original Minecraft name written
    // by the developer. Apply these before any heuristic pass so they get HIGH confidence.
    static void pass0ShadowMembers(RenameContext ctx) {
        Map<String, ClassMeta> metaMap = ctx.metaMap;
        Map<String, Rename> fieldRenames = ctx.fieldRenames;
        Map<String, Rename> methodRenames = ctx.methodRenames;
        Map<String, Set<String>> reservedMethodSigs = ctx.reservedMethodSigs;
        Map<String, Set<String>> reservedFieldNames = ctx.reservedFieldNames;
        for (Map.Entry<String, ClassMeta> classEntry : metaMap.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            ClassMeta meta = classEntry.getValue();
            if (meta.mixinTarget == null) continue; // only meaningful inside @Mixin classes

            for (Map.Entry<String, String> sf : meta.shadowFields.entrySet()) {
                String obfName = sf.getKey();
                String realName = sf.getValue();
                if (isAlreadyReadable(obfName)) continue;
                if (!isAlreadyReadable(realName)) continue; // shadow name must itself be readable
                String key = cls + "." + obfName;
                if (fieldRenames.containsKey(key)) continue;
                String unique = uniqueMember(realName,
                        reservedFieldNames.computeIfAbsent(cls, k -> new HashSet<>()));
                if (unique != null) {
                    fieldRenames.put(key, new Rename(unique, Confidence.HIGH));
                    if (VERBOSE) System.out.println("  SHADOW FIELD  " + obfName + " -> " + unique);
                }
            }

            for (Map.Entry<String, String> sm : meta.shadowMethods.entrySet()) {
                String nameAndDesc = sm.getKey();
                String realName = sm.getValue();
                int paren = nameAndDesc.indexOf('(');
                String obfName = nameAndDesc.substring(0, paren);
                String desc    = nameAndDesc.substring(paren);
                if (isAlreadyReadable(obfName)) continue;
                if (!isAlreadyReadable(realName)) continue;
                String key = cls + "." + nameAndDesc;
                if (methodRenames.containsKey(key)) continue;
                Set<String> reserved = reservedMethodSigs.computeIfAbsent(cls, k -> new HashSet<>());
                String unique = uniqueMethodName(realName, desc, reserved);
                methodRenames.put(key, new Rename(unique, Confidence.HIGH));
                if (VERBOSE) System.out.println("  SHADOW METHOD " + obfName + " -> " + unique);
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 1: Mixin annotations ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Classes annotated with @Mixin(SomeTarget.class) are named after their target ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â highest
    // confidence because the developer explicitly wrote the target class name.
    static void pass1MixinTarget(RenameContext ctx) {
        Map<String, ClassMeta> metaMap = ctx.metaMap;
        Map<String, Rename> classRenames = ctx.classRenames;
        Set<String> usedClassNames = ctx.usedClassNames;
        for (Map.Entry<String, ClassMeta> classEntry : metaMap.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            ClassMeta meta = classEntry.getValue();
            if (meta.mixinTarget == null) continue;
            if (isAlreadyReadable(simpleClassName(cls))) continue;

            String targetSimple = simpleClassName(meta.mixinTarget);
            String proposed = "Mixin" + targetSimple;
            String full = qualifyAndReserve(ctx, cls, proposed);
            if (full == null) continue;

            classRenames.put(cls, new Rename(full, Confidence.HIGH));
            usedClassNames.add(full);
            if (VERBOSE) System.out.println("  MIXIN  " + simpleClassName(cls) + " -> " + simpleClassName(full)
                    + "  (targets " + targetSimple + ")");
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 2: String-anchor based naming ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Scores all string literals found in each class; the best-scoring anchor becomes the
    // proposed class name. Also assigns field renames from field-associated anchors.
    static void pass2StringAnchors(RenameContext ctx) {
        Map<String, List<StringAnchor>> anchors = ctx.anchors;
        Map<String, ClassMeta> metaMap = ctx.metaMap;
        Map<String, Rename> classRenames = ctx.classRenames;
        Map<String, Rename> fieldRenames = ctx.fieldRenames;
        Map<String, Integer> anchorFrequency = ctx.anchorFrequency;
        Set<String> usedClassNames = ctx.usedClassNames;
        Map<String, Set<String>> reservedFieldNames = ctx.reservedFieldNames;
        for (Map.Entry<String, List<StringAnchor>> classEntry : anchors.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            if (classRenames.containsKey(cls)) continue;
            if (isAlreadyReadable(simpleClassName(cls))) continue;
            // Skip string pool classes ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â their strings are payloads, not semantic names
            ClassMeta meta2 = metaMap.get(cls);
            if (meta2 != null && meta2.isStringTable) continue; // string pool ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â naming it would be misleading

            List<StringAnchor> list = classEntry.getValue();
            StringAnchor best = pickBestAnchor(list, anchorFrequency);
            if (best == null) continue;

            String proposed = sanitizeClassName(best.value);
            if (proposed == null || proposed.isEmpty()) continue;

            String full = qualifyAndReserve(ctx, cls, proposed);
            if (full == null) continue;

            Confidence conf = (best.type == AnchorType.EXTERNAL) ? Confidence.HIGH : Confidence.MEDIUM;
            classRenames.put(cls, new Rename(full, conf));
            usedClassNames.add(full);
            if (VERBOSE) System.out.println("  CLASS  " + simpleClassName(cls) + " -> " + simpleClassName(full)
                    + "  (\"" + best.value + "\" score=" + String.format("%.2f", best.score)
                    + " freq=" + anchorFrequency.getOrDefault(best.value, 1) + ")");

            // Field renames from the same class's anchors
            for (StringAnchor a : list) {
                if (a.fieldName == null || isAlreadyReadable(a.fieldName)) continue;
                if (a.score < MIN_SCORE || a.type == AnchorType.NOISE) continue;
                // Apply frequency penalty to field anchors the same way pickBestAnchor does for classes
                int freq = anchorFrequency.getOrDefault(a.value, 1);
                double adjusted = adjustedAnchorScore(a.score, a.type, freq);
                if (adjusted < ANCHOR_MIN_ADJUSTED) continue;
                if (fieldRenames.containsKey(cls + "." + a.fieldName)) continue;
                String fProposed = sanitizeFieldName(a.value, a.type);
                if (fProposed == null) continue;
                fProposed = uniqueMember(fProposed,
                        reservedFieldNames.computeIfAbsent(cls, k -> new HashSet<>()));
                if (fProposed == null) continue;
                fieldRenames.put(cls + "." + a.fieldName, new Rename(fProposed, conf));
            }
        }
    }

    // Pass 2b: field-only rename for classes that didn't get a class rename.
    // Fields in classes skipped by pass 2 (readable name, no good class anchor)
    // still get renamed if they have strong field-associated string anchors.
    static void pass2bFieldOnly(RenameContext ctx) {
        Map<String, List<StringAnchor>> anchors = ctx.anchors;
        Map<String, Rename> classRenames = ctx.classRenames;
        Map<String, Rename> fieldRenames = ctx.fieldRenames;
        Map<String, Integer> anchorFrequency = ctx.anchorFrequency;
        Map<String, Set<String>> reservedFieldNames = ctx.reservedFieldNames;
        for (Map.Entry<String, List<StringAnchor>> classEntry : anchors.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            // Only process classes that were NOT renamed in pass 2
            if (classRenames.containsKey(cls)) continue;
            List<StringAnchor> list = classEntry.getValue();
            for (StringAnchor a : list) {
                if (a.fieldName == null || isAlreadyReadable(a.fieldName)) continue;
                if (a.score < MIN_SCORE || a.type == AnchorType.NOISE) continue;
                if (fieldRenames.containsKey(cls + "." + a.fieldName)) continue;
                if (NOISE_WORDS.contains(a.value.toLowerCase())) continue;
                // Apply frequency penalty so high-frequency strings don't rename every field they touch
                int freq = anchorFrequency.getOrDefault(a.value, 1);
                double adjusted = adjustedAnchorScore(a.score, a.type, freq);
                if (adjusted < ANCHOR_MIN_ADJUSTED) continue;
                String fProposed = sanitizeFieldName(a.value, a.type);
                if (fProposed == null) continue;
                fProposed = uniqueMember(fProposed,
                        reservedFieldNames.computeIfAbsent(cls, k -> new HashSet<>()));
                if (fProposed == null) continue;
                Confidence conf = (a.type == AnchorType.EXTERNAL) ? Confidence.HIGH : Confidence.MEDIUM;
                fieldRenames.put(cls + "." + a.fieldName, new Rename(fProposed, conf));
                if (VERBOSE) System.out.println("  FIELD  " + cls + "." + a.fieldName + " -> " + fProposed);
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 2.5: Exception/Error subclass detection ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Classes that extend a known Exception or Error are named with an "Exception" suffix, using
    // any available string anchor as a meaningful prefix.
    static void pass2_5ExceptionSubclass(RenameContext ctx) {
        Map<String, ClassMeta> metaMap = ctx.metaMap;
        Map<String, List<StringAnchor>> anchors = ctx.anchors;
        Map<String, Rename> classRenames = ctx.classRenames;
        Map<String, Integer> anchorFrequency = ctx.anchorFrequency;
        Set<String> usedClassNames = ctx.usedClassNames;
        for (Map.Entry<String, ClassMeta> classEntry : metaMap.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            if (classRenames.containsKey(cls)) continue;
            if (isAlreadyReadable(simpleClassName(cls))) continue;

            ClassMeta meta = classEntry.getValue();
            if (meta.superName == null) continue;
            boolean isExc = meta.superName.endsWith("Exception") || meta.superName.endsWith("Error");
            if (!isExc) continue;

            // Try to find a string anchor to name it
            List<StringAnchor> localAnchors = anchors.get(cls);
            StringAnchor best = pickBestAnchor(localAnchors, anchorFrequency);
            String proposed;
            if (best != null) {
                String base = sanitizeClassName(best.value);
                proposed = (base != null && !base.isEmpty()) ? base + "Exception" : "CustomException";
            } else {
                proposed = "CustomException";
            }
            String full = qualifyAndReserve(ctx, cls, proposed);
            if (full == null) continue;
            classRenames.put(cls, new Rename(full, Confidence.MEDIUM));
            usedClassNames.add(full);
            if (VERBOSE) System.out.println("  EXCEPT " + simpleClassName(cls) + " -> " + simpleClassName(full)
                    + "  (extends " + simpleClassName(meta.superName) + ")");
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 3: Structural intelligence ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Uses class-level shape (interfaces, enums, annotations, Vector shapes, Managers, Utils)
    // to assign a generic but meaningful name when string anchors produced nothing.
    static void pass3Structural(RenameContext ctx) {
        Map<String, ClassMeta> metaMap = ctx.metaMap;
        Map<String, Rename> classRenames = ctx.classRenames;
        Set<String> usedClassNames = ctx.usedClassNames;
        for (Map.Entry<String, ClassMeta> classEntry : metaMap.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            if (classRenames.containsKey(cls)) continue;
            if (isAlreadyReadable(simpleClassName(cls))) continue;

            ClassMeta meta = classEntry.getValue();
            String proposed = null;

            if (meta.isAnnotation) {
                proposed = "Annotation";
            } else if (meta.isEnum) {
                // Enums are deliberately skipped here to avoid misclassifying as Utility
                // (their values()/valueOf() are static). Pass 2 string anchors already handle them.
                continue;
            } else if (meta.isInterface) {
                if (meta.abstractMethodCount == 1) {
                    // Classify functional interfaces by return type of the single abstract method.
                    // Uses only abstract methods so static/default helper methods added in Java 8+
                    // don't corrupt the Consumer vs Function decision.
                    if (meta.abstractMethodsReturnVoid) proposed = "Consumer";
                    else proposed = "Function";
                } else if (meta.abstractMethodCount >= 2 && meta.abstractMethodsReturnVoid) {
                    proposed = "Listener";
                } else if (meta.abstractMethodCount >= 2) {
                    proposed = "Interface";
                }
            } else if (meta.doubleFieldCount == 3 && meta.fieldCount == 3) {
                proposed = "Vector3";
            } else if (meta.doubleFieldCount == 2 && meta.fieldCount == 2) {
                proposed = "Vector2";
            } else if (meta.hasPrivateCtor && meta.hasStaticInstance && meta.methodCount > 3) {
                proposed = "Manager";
            } else if (meta.methodCount > 0 && meta.allStaticMethods) {
                proposed = "Utility";
            }

            if (proposed != null) {
                String full = qualifyAndReserve(ctx, cls, proposed);
                if (full == null) continue;

                Rename rename = new Rename(full, Confidence.LOW);
                if (INTERACTIVE) {
                    rename = promptUser(cls, rename, "Structural (" + proposed + ")");
                    if (rename == null) continue; // user skipped ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â keep original
                }

                classRenames.put(cls, rename);
                usedClassNames.add(rename.name);
                if (VERBOSE) System.out.println("  STRUCT " + simpleClassName(cls) + " -> " + simpleClassName(rename.name)
                        + "  (type=" + proposed + ")");
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 4: Hierarchy propagation ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // If a superclass was renamed in a prior pass, its subclasses are named "<Super>_Impl" or
    // "<Super>_<AnchorToken>". Runs in a fixpoint loop so chained hierarchies (A->B->C) all
    // get renamed even when B and C are visited in reverse order on the first iteration.
    static void pass4Hierarchy(RenameContext ctx) {
        Map<String, ClassMeta> metaMap = ctx.metaMap;
        Map<String, List<StringAnchor>> anchors = ctx.anchors;
        Map<String, Rename> classRenames = ctx.classRenames;
        Map<String, Integer> anchorFrequency = ctx.anchorFrequency;
        Set<String> usedClassNames = ctx.usedClassNames;
        boolean pass4Changed = true;
        while (pass4Changed) {
            pass4Changed = false;
        for (Map.Entry<String, ClassMeta> classEntry : metaMap.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            if (classRenames.containsKey(cls)) continue;
            if (isAlreadyReadable(simpleClassName(cls))) continue;

            ClassMeta meta = classEntry.getValue();
            Rename superRenamed = meta.superName != null ? classRenames.get(meta.superName) : null;
            if (superRenamed == null) continue;

            // Try to find a local anchor to combine with super name.
            // Strip any "_Impl" or "_Impl_N" suffix (including collision suffixes like "_Impl_2")
            // from the base before appending ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â prevents "Utility_3_Impl_2_Impl_3" chains when
            // a hierarchy is more than two levels deep. All children of any depth share the same
            // base name and are distinguished only by the collision counter.
            String baseProp = simpleClassName(superRenamed.name);
            // Strip trailing "_Impl" optionally followed by "_N" digit suffix
            String basePropStripped = baseProp.replaceAll("_Impl(_\\d+)?$", "");
            if (basePropStripped.isEmpty()) basePropStripped = baseProp; // safety fallback
            List<StringAnchor> localAnchors = anchors.get(cls);
            StringAnchor localBest = pickBestAnchor(localAnchors, anchorFrequency);
            String fullProp = (localBest != null)
                    ? basePropStripped + "_" + sanitizeClassName(localBest.value)
                    : basePropStripped + "_Impl";

            String full = qualifyAndReserve(ctx, cls, fullProp);
            if (full == null) continue;

            Rename rename = new Rename(full, Confidence.LOW);
            if (INTERACTIVE) {
                rename = promptUser(cls, rename, "Hierarchy (extends " + simpleClassName(superRenamed.name) + ")");
                if (rename == null) continue; // user skipped ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â keep original
            }

            classRenames.put(cls, rename);
            usedClassNames.add(rename.name);
            pass4Changed = true;
            if (VERBOSE) System.out.println("  HIER   " + simpleClassName(cls) + " -> " + simpleClassName(rename.name)
                    + "  (extends " + simpleClassName(superRenamed.name) + ")");
        }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 5: Inner class propagation ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Once the outer class has a readable name, nest inner classes under it using the "$"
    // separator so the output mirrors normal Java inner-class naming conventions.
    static void pass5InnerClasses(RenameContext ctx) {
        Map<String, ClassMeta> metaMap = ctx.metaMap;
        Map<String, Rename> classRenames = ctx.classRenames;
        Set<String> usedClassNames = ctx.usedClassNames;
        Set<String> originalClassNames = ctx.originalClassNames;
        Map<String, Integer> nameCollisionCounts = ctx.nameCollisionCounts;
        for (Map.Entry<String, ClassMeta> classEntry : metaMap.entrySet()) {
            String cls = classEntry.getKey();
            if (isLibraryClass(cls)) continue;
            ClassMeta meta = classEntry.getValue();
            if (meta.isInnerClass && meta.outerClass != null) {
                Rename outerRenamed = classRenames.get(meta.outerClass);
                if (outerRenamed != null) {
                    if (classRenames.containsKey(cls)) {
                        // Already renamed via anchor ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â re-nest under the new outer name.
                        // Use uniqueName to prevent two inner classes that both happened to
                        // receive the same anchor-derived simple name from colliding.
                        Rename current = classRenames.get(cls);
                        String simple = simpleClassName(current.name);
                        String nested = outerRenamed.name + "$" + simple;
                        String full = uniqueName(nested, originalClassNames, usedClassNames, nameCollisionCounts);
                        if (full == null) continue;
                        classRenames.put(cls, new Rename(full, current.confidence));
                        usedClassNames.add(full);
                    } else {
                        // Not renamed yet, give it a generic inner name
                        String base = simpleClassName(cls);
                        if (!isAlreadyReadable(base)) base = "Inner";
                        String nested = outerRenamed.name + "$" + base;
                        String full = uniqueName(nested, originalClassNames, usedClassNames, nameCollisionCounts);
                        if (full == null) continue;
                        classRenames.put(cls, new Rename(full, Confidence.LOW));
                        usedClassNames.add(full);
                    }
                }
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 7: package-level renaming ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // For packages where all segments are short/obfuscated (ÃƒÂ¢Ã¢â‚¬Â°Ã‚Â¤3 chars each), collect the
    // renamed classes in that package and derive a package alias from the most common
    // meaningful word in their new simple names. Updates the already-renamed class entries
    // to include the new package suffix ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no bytecode change needed for class identity,
    // but makes the output far more navigable when the remapper writes the JAR.
    static void pass7PackageRename(RenameContext ctx) {
        Map<String, Rename> classRenames = ctx.classRenames;

        // Stop-words for package theme: structural/synthetic names invented by the remapper
        // itself (passes 3/4) must not feed back as theme words ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â that produces self-referential
        // nonsense like "net.impl" or "a.b.c.utility".
        Set<String> themeStopWords = new HashSet<>(NOISE_WORDS);
        themeStopWords.addAll(Arrays.asList(
                "impl", "utility", "function", "consumer", "listener", "interface",
                "annotation", "manager2", "vector2", "vector3", "exception",
                "inner", "custom", "base"));

        Map<String, List<Map.Entry<String, Rename>>> packageToEntries = new HashMap<>();
        for (Map.Entry<String, Rename> entry : classRenames.entrySet()) {
            String pkg = packageOf(entry.getKey());
            if (!isObfuscatedPackage(pkg)) continue;
            // Only include MEDIUM or HIGH confidence renames as theme sources ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â LOW confidence
            // means the name was invented by structural/hierarchy passes, not anchored to a string.
            if (entry.getValue().confidence == Confidence.LOW) continue;
            packageToEntries.computeIfAbsent(pkg, k -> new ArrayList<>()).add(entry);
        }

        for (Map.Entry<String, List<Map.Entry<String, Rename>>> pe : packageToEntries.entrySet()) {
            String obfPkg = pe.getKey();
            List<Map.Entry<String, Rename>> entries = pe.getValue();
            if (entries.size() < 3) continue;

            // Find the most common "theme word" across MEDIUM/HIGH renamed class simple names.
            // Strip inner-class suffixes ($Inner) before splitting so "$" doesn't appear in words.
            Map<String, Integer> wordFreq = new HashMap<>();
            for (Map.Entry<String, Rename> e : entries) {
                String simple = simpleClassName(e.getValue().name);
                // Drop inner class portion ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â "Outer$Inner" ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ "Outer"
                int dollar = simple.indexOf('$');
                if (dollar > 0) simple = simple.substring(0, dollar);
                for (String word : simple.split("(?=[A-Z])|_")) {
                    String lw = word.toLowerCase();
                    if (lw.length() >= 4 && !themeStopWords.contains(lw))
                        wordFreq.merge(lw, 1, Integer::sum);
                }
            }
            if (wordFreq.isEmpty()) continue;

            String themeWord = wordFreq.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(null);
            if (themeWord == null) continue;

            // Update every class in this obfuscated package to include the theme word as a suffix
            // on the package ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â iterate over a snapshot to avoid ConcurrentModificationException
            List<Map.Entry<String, Rename>> snapshot = new ArrayList<>(classRenames.entrySet());
            for (Map.Entry<String, Rename> ce : snapshot) {
                if (!packageOf(ce.getKey()).equals(obfPkg)) continue;
                Rename existing = ce.getValue();
                String newPkg = obfPkg + "." + themeWord;
                String newFull = newPkg + "." + simpleClassName(existing.name);
                classRenames.put(ce.getKey(), new Rename(newFull, existing.confidence));
                if (VERBOSE) System.out.println("  PKG    " + obfPkg + " -> " + newPkg
                        + "  (theme=" + themeWord + ")");
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Inline decryption ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    /** Per-class wall-clock budget for inline decryption, in milliseconds.
     *  A malicious or heavy &lt;clinit&gt; can hang or spin; this bounds it. */
    static final long DECRYPT_TIMEOUT_MS = 4000;

    /**
     * Best-effort inline string decryption: loads each class so its
     * &lt;clinit&gt; runs the obfuscator's decryption routine, then reads back
     * static String fields. This is inherently UNSAFE (it executes attacker
     * bytecode) and, unlike ENI_StringDumper, performs no anti-analysis
     * patching or stubbing ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â so on heavily protected JARs most classes will
     * fail to initialise. Each class is therefore run under a wall-clock
     * timeout and all failures are counted and reported, so the run is honest
     * about how little (or much) it actually recovered instead of silently
     * doing nothing.
     */
    static void decryptInline(Map<String, byte[]> classes, Map<String, List<String>> externalStrings) {
        MemoryClassLoader loader = new MemoryClassLoader(classes);
        java.util.concurrent.atomic.AtomicReference<java.util.concurrent.ExecutorService> execRef =
            new java.util.concurrent.atomic.AtomicReference<>(
                java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                    Thread t = new Thread(r, "decrypt-clinit");
                    t.setDaemon(true);
                    return t;
                }));

        int ok = 0, failed = 0, timedOut = 0;
        try {
            for (String className : classes.keySet()) {
                java.util.concurrent.Future<Integer> fut = execRef.get().submit(() -> {
                    int added = 0;
                    Class<?> cls = Class.forName(className, true, loader);
                    for (java.lang.reflect.Field f : cls.getDeclaredFields()) {
                        if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                        if (f.getType() != String.class) continue;
                        try {
                            f.setAccessible(true);
                            String val = (String) f.get(null);
                            if (val != null && !val.isEmpty()) {
                                externalStrings.computeIfAbsent(className, k -> new ArrayList<>()).add(val);
                                added++;
                            }
                        } catch (Throwable ignored) {}
                    }
                    return added;
                });
                try {
                    fut.get(DECRYPT_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
                    ok++;
                } catch (java.util.concurrent.TimeoutException te) {
                    fut.cancel(true);
                    timedOut++;
                    execRef.get().shutdownNow();
                    execRef.set(java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                        Thread t2 = new Thread(r, "decrypt-clinit");
                        t2.setDaemon(true);
                        return t2;
                    }));
                    if (VERBOSE) System.out.println("[!] Inline decryption timeout at " + className + ", continuing...");
                } catch (Throwable t) {
                    failed++;
                }
            }
        } finally {
            execRef.get().shutdownNow();
        }
        reportDecrypt(ok, failed, timedOut);
    }



    static void reportDecrypt(int ok, int failed, int timedOut) {
        System.out.println("[*] Inline decryption: " + ok + " classes initialised, "
                + failed + " failed, " + timedOut + " timed out.");
    }

    static class MemoryClassLoader extends ClassLoader {
        private final Map<String, byte[]> classes;
        public MemoryClassLoader(Map<String, byte[]> classes) {
            super(ClassLoader.getSystemClassLoader());
            this.classes = classes;
        }
        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] b = classes.get(name);
            if (b == null) return super.findClass(name);
            return defineClass(name, b, 0, b.length);
        }
    }

    static void runDecompiler(File outputJar) {
        File dir = outputJar.getParentFile();
        File cfrJar = null;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.getName().toLowerCase().startsWith("cfr") && f.getName().toLowerCase().endsWith(".jar")) {
                    cfrJar = f;
                    break;
                }
            }
        }

        if (cfrJar == null) {
            System.out.println("[!] CFR decompiler not found in " + dir.getAbsolutePath() + ". Skipping decompilation.");
            System.out.println("    Download it from: https://www.benf.org/other/cfr/");
            return;
        }

        System.out.println("[*] Running CFR decompiler...");
        File srcDir = new File(dir, "src");
        srcDir.mkdirs();
        try {
            // Extra flags improve output quality on obfuscated bytecode:
            //   --recovertypeclash    handles bad operand-stack types from obfuscation
            //   --forcetopsort        better control-flow reconstruction on mangled CFGs
            //   --decodefinally false stops CFR mangling obfuscated try/catch blocks
            //   --stringbuffer        reconstructs StringBuilder chains into string literals
            //   --silent              suppresses per-class warnings (very noisy on obfuscated jars)
            //   --caseinsensitivefs   required on Windows to avoid output path collisions
            Process p = new ProcessBuilder(
                    "java", "-jar", cfrJar.getName(), outputJar.getName(),
                    "--outputdir", "src",
                    "--recovertypeclash", "true",
                    "--forcetopsort", "true",
                    "--decodefinally", "false",
                    "--stringbuffer", "true",
                    "--silent", "true",
                    "--caseinsensitivefs", "true")
                    .directory(dir)
                    .inheritIO()
                    .start();
            p.waitFor();
            System.out.println("[+] Decompiled source to: " + srcDir.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("[-] Decompiler failed: " + e.getMessage());
        }
    }

    /** Frequency-penalised anchor score. EXTERNAL/FIELD_CONST anchors are class-specific by
     *  nature, so they get the gentler sqrt penalty up to {@link #FREQ_SQRT_THRESHOLD}; above
     *  that (and for all other anchor types) a linear penalty applies so a string appearing in
     *  hundreds of classes (e.g. a shared crypto constant) can't win a class name. */
    static double adjustedAnchorScore(double score, AnchorType type, int frequency) {
        boolean classSpecific = (type == AnchorType.EXTERNAL || type == AnchorType.FIELD_CONST);
        if (classSpecific && frequency <= FREQ_SQRT_THRESHOLD)
            return score / Math.sqrt(frequency);
        return score / (double) frequency;
    }

    static StringAnchor pickBestAnchor(List<StringAnchor> list, Map<String, Integer> anchorFrequency) {
        if (list == null) return null;
        StringAnchor best = null;
        double bestScore = -1;
        for (StringAnchor anchor : list) {
            if (anchor.score < MIN_SCORE || anchor.type == AnchorType.NOISE) continue;
            if (NOISE_WORDS.contains(anchor.value.toLowerCase())) continue;
            // Require minimum anchor length of 5 chars for class naming
            if (anchor.value.length() < 5) continue;
            int frequency = anchorFrequency.getOrDefault(anchor.value, 1);
            double adjusted = adjustedAnchorScore(anchor.score, anchor.type, frequency);
            // Drop anchors that appear in so many classes they carry no useful signal
            if (adjusted < ANCHOR_MIN_ADJUSTED) continue;
            if (adjusted > bestScore) { bestScore = adjusted; best = anchor; }
        }
        return best;
    }

    /** Heuristic name from a method signature. Deliberately conservative: it
     *  only returns a guess for signatures that carry a *distinctive* shape
     *  (typed setters, byte[] (de)serialisers, collection getters, comparators).
     *  Broad no-arg shapes return null (left obfuscated) so the mapping only
     *  contains renames we can actually justify. Call-site analysis in pass 6
     *  still promotes clear entry points to "init" / "setup". */
    static String guessMethodName(String original, String descriptor, int access) {
        int close = descriptor.lastIndexOf(')');
        String ret  = descriptor.substring(close + 1);
        String args = descriptor.substring(1, close);
        boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;

        // Varargs array dispatchers are ubiquitous in obfuscated clients ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â any single-arg void
        // method whose only parameter is a reference array type ([Lsome/Type;) is a synthetic
        // trampoline. They carry zero information about what the method actually does.
        if (ARRAY_VARARG_ARGS.matcher(args).matches()) return null;

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â setters
        // Typed single-argument setters ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the arg type makes these specific.
        if (ret.equals("V") && args.equals("Z"))                      return "setEnabled";
        // Don't rename (String)void to "setName" ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â too many methods take a String arg.

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â serialisation / IO
        // Distinctive (de)serialisation shapes.
        if (ret.equals("[B")             && args.isEmpty())            return "toBytes";
        // I/O shapes ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â byte[] and streams.
        if (ret.equals("[B") && args.equals("Ljava/io/InputStream;")) return "readBytes";
        if (ret.equals("V")  && args.equals("Ljava/io/OutputStream;"))return "writeTo";
        // Crypto / transform shape ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â byte[] in, byte[] out. Very common in obfuscated JARs.
        if (ret.equals("[B") && args.equals("[B"))                     return "transform";

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â collection shapes
        if (ret.equals("Ljava/util/List;") && args.isEmpty())         return "getList";
        if (ret.equals("Ljava/util/Map;")  && args.isEmpty())         return "getMap";
        // Collection contains shape ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Object-in boolean-out.
        if (ret.equals("Z") && args.equals("Ljava/lang/Object;"))     return "contains";
        // Comparator shape ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â highly distinctive two-Object int return.
        if (ret.equals("I") && args.equals("Ljava/lang/Object;Ljava/lang/Object;")) return "compare";

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â functional interfaces
        // Static factory / parse shape ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â static, String in, reference type out.
        if (isStatic && ret.startsWith("L") && args.equals("Ljava/lang/String;")) return "parse";

        // Broad shapes ("()V", "()Z", "()I", "()D", generic getters/setters)
        // are intentionally NOT guessed: they collide en masse and add no real
        // information. Returning null leaves them with their original names.
        return null;
    }

    static String uniqueName(String proposed, Set<String> existing,
                              Set<String> used, Map<String, Integer> collisions) {
        if (!existing.contains(proposed) && !used.contains(proposed)) return proposed;
        // Suffix with _2, _3 etc. rather than dropping entirely ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â a numbered name is
        // still more useful than leaving the class with its original obfuscated name.
        for (int i = 2; i <= 50; i++) {
            String candidate = proposed + "_" + i;
            if (!existing.contains(candidate) && !used.contains(candidate)) return candidate;
        }
        collisions.merge(proposed, 1, Integer::sum);
        return null;
    }

    /** Qualifies a proposed simple class name with {@code cls}'s package and returns a
     *  collision-free full name (or null if every candidate is taken). Centralises the
     *  packageOf + "pkg.Name" + uniqueName boilerplate shared by the class-naming passes.
     *  Does NOT register the name in usedClassNames â€” the caller does that after any
     *  interactive override, so the registered name always matches the one actually used. */
    static String qualifyAndReserve(RenameContext ctx, String cls, String proposedSimple) {
        String pkg = packageOf(cls);
        String qualified = pkg.isEmpty() ? proposedSimple : pkg + "." + proposedSimple;
        return uniqueName(qualified, ctx.originalClassNames, ctx.usedClassNames, ctx.nameCollisionCounts);
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Member-collision safety ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    //
    // A class may not declare two methods with the same name+descriptor, nor two
    // fields with the same name. The rename heuristics happily map many distinct
    // members onto the same readable name (e.g. every "()V" -> "reset"), which
    // previously corrupted the output JAR. These helpers reserve the chosen name
    // per owner and suffix on collision so the result is always valid bytecode.

    /** Records the original method signatures (name+desc) and field names of
     *  every class, so renames can't collide with members we didn't touch.
     *  Also populates fieldDescriptors ("owner.fieldName" -> descriptor) for
     *  use in Tiny v2 mapping output which requires field descriptors. */
    static void collectOriginalMembers(Map<String, byte[]> classes,
                                        Map<String, Set<String>> methodSigs,
                                        Map<String, Set<String>> fieldNames,
                                        Map<String, String> fieldDescriptors) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            String cls = classEntry.getKey();
            Set<String> methodSigsForClass = methodSigs.computeIfAbsent(cls, k -> new HashSet<>());
            Set<String> fieldNamesForClass  = fieldNames.computeIfAbsent(cls, k -> new HashSet<>());
            try {
                new ClassReader(classEntry.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public FieldVisitor visitField(int a, String n, String d, String s, Object v) {
                        fieldNamesForClass.add(n);
                        fieldDescriptors.put(cls + "." + n, d);
                        return null;
                    }
                    @Override
                    public MethodVisitor visitMethod(int a, String n, String d, String s, String[] ex) {
                        methodSigsForClass.add(n + d);
                        return null;
                    }
                }, ClassReader.SKIP_CODE | ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            } catch (Throwable ignored) {}
        }
    }

    /** Returns a method name for {@code desc} that doesn't already exist in
     *  {@code reserved} (a set of name+descriptor strings for one owner). The
     *  chosen signature is added to {@code reserved}. Never returns null in
     *  practice (suffixing always terminates). */
    static String uniqueMethodName(String base, String desc, Set<String> reserved) {
        if (reserved.add(base + desc)) return base;
        for (int n = 2; ; n++) {
            String candidate = base + n;
            if (reserved.add(candidate + desc)) return candidate;
        }
    }

    /** Returns a field name not already present in {@code reserved} (field names
     *  for one owner), adding the chosen name to it. */
    static String uniqueMember(String base, Set<String> reserved) {
        if (base == null) return null;
        if (reserved.add(base)) return base;
        for (int n = 2; ; n++) {
            String candidate = base + n;
            if (reserved.add(candidate)) return candidate;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ JAR writing ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    static void writeRemappedJar(Map<String, byte[]> classes,
                                  Map<String, byte[]> resources,
                                  Map<String, Rename> classRenames,
                                  Map<String, Rename> fieldRenames,
                                  Map<String, Rename> methodRenames,
                                  File outputJar,
                                  Map<String, String> superMap) throws IOException {
        Map<String, String> internalRenames = new HashMap<>();
        for (Map.Entry<String, Rename> e : classRenames.entrySet())
            internalRenames.put(internal(e.getKey()), internal(e.getValue().name));

        Remapper remapper = new Remapper() {
            /** Remaps class internal names (slash-separated) to their renamed equivalents. */
            @Override
            public String map(String internalName) {
                return internalRenames.getOrDefault(internalName, internalName);
            }

            /** Remaps field names within a given owner class. */
            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                String key = binary(owner) + "." + name;
                Rename r = fieldRenames.get(key);
                return r != null ? r.name : name;
            }

            /** Remaps method names within a given owner class, matched by name and descriptor. */
            @Override
            public String mapMethodName(String owner, String name, String descriptor) {
                String key = binary(owner) + "." + name + descriptor;
                Rename r = methodRenames.get(key);
                return r != null ? r.name : name;
            }
        };

        Set<String> written = new HashSet<>();
        // ClassWriter with COMPUTE_FRAMES so renamed type references in stack map
        // frames are recomputed correctly. We use the superMap built from metaData
        // to give ASM a proper class hierarchy instead of always returning Object.
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(outputJar))) {
            for (Map.Entry<String, byte[]> e : classes.entrySet()) {
                byte[] remapped;
                try {
                    ClassReader cr = new ClassReader(e.getValue());
                    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES) {
                        @Override
                        protected String getCommonSuperClass(String type1, String type2) {
                            if (type1.equals(type2)) return type1;
                            // Collect type1's ancestor chain (using post-rename internal names)
                            Set<String> ancestors = new LinkedHashSet<>();
                            String cur = type1;
                            int guard = 64;
                            while (cur != null && !cur.equals("java/lang/Object") && guard-- > 0) {
                                ancestors.add(cur);
                                cur = superMap.get(cur);
                            }
                            ancestors.add("java/lang/Object");
                            // Walk type2's chain; return first ancestor found in type1's chain
                            cur = type2;
                            guard = 64;
                            while (cur != null && guard-- > 0) {
                                if (ancestors.contains(cur)) return cur;
                                String next = superMap.get(cur);
                                if (next == null) break;
                                cur = next;
                            }
                            return "java/lang/Object";
                        }
                    };
                    cr.accept(new ClassRemapper(cw, remapper) {
                        @Override
                        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exceptions) {
                            MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);
                            return new MethodVisitor(Opcodes.ASM9, mv) {
                                @Override
                                public void visitLdcInsn(Object cst) {
                                    if (cst instanceof String) {
                                        String s = (String) cst;
                                        // Try dot format
                                        Rename r = classRenames.get(s);
                                        if (r != null) { super.visitLdcInsn(r.name); return; }
                                        // Try internal format
                                        String dot = binary(s);
                                        r = classRenames.get(dot);
                                        if (r != null) { super.visitLdcInsn(internal(r.name)); return; }
                                    }
                                    super.visitLdcInsn(cst);
                                }
                            };
                        }
                    }, ClassReader.EXPAND_FRAMES);
                    remapped = cw.toByteArray();
                } catch (Throwable t) {
                    remapped = e.getValue();
                }

                Rename r = classRenames.get(e.getKey());
                String newName  = r != null ? r.name : e.getKey();
                String entryName = internal(newName) + ".class";
                if (!written.add(entryName)) continue;
                jos.putNextEntry(new JarEntry(entryName));
                jos.write(remapped);
                jos.closeEntry();
            }

            for (Map.Entry<String, byte[]> e : resources.entrySet()) {
                if (e.getKey().equals("META-INF/MANIFEST.MF")) continue;
                if (!written.add(e.getKey())) continue;
                try {
                    jos.putNextEntry(new JarEntry(e.getKey()));
                    jos.write(e.getValue());
                    jos.closeEntry();
                } catch (Exception ignored) {}
            }

            jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
            jos.write("Manifest-Version: 1.0\n".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Mapping file output ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    static void writeMappingFile(Map<String, Rename> classRenames,
                                  Map<String, Rename> fieldRenames,
                                  Map<String, Rename> methodRenames,
                                  File mapFile,
                                  File inputJar) throws IOException {
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(mapFile), StandardCharsets.UTF_8))) {
            out.println("# JarRemapper mapping");
            out.println("# Source  : " + inputJar.getName());
            out.println("# Date    : " + new java.util.Date());
            out.println("# Params  : score=" + MIN_SCORE + "  minlen=" + MIN_LEN + "  maxlen=" + MAX_LEN);
            out.println("# CLASS  original -> renamed [CONFIDENCE]");
            out.println("# FIELD  owner.name -> renamed [CONFIDENCE]");
            out.println("# METHOD owner.name+descriptor -> renamed [CONFIDENCE]");
            out.println();
            classRenames.forEach((k, v)  -> out.println("CLASS  " + k + " -> " + v.name + " [" + v.confidence + "]"));
            out.println();
            fieldRenames.forEach((k, v)  -> out.println("FIELD  " + k + " -> " + v.name + " [" + v.confidence + "]"));
            out.println();
            methodRenames.forEach((k, v) -> out.println("METHOD " + k + " -> " + v.name + " [" + v.confidence + "]"));
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Mapping key helpers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    /** Parsed rename-map key. Keys are "owner.name" (fields) or "owner.name(descriptor)"
     *  (methods), where owner is a binary (dot) class name. Centralises the substring/indexOf
     *  parsing that the SRG/Tiny writers previously each did inline. */
    static final class MemberKey {
        final String ownerDot;  // "com.example.Foo"
        final String name;      // "doThing"
        final String desc;      // "(I)V" for methods, "" for fields
        private MemberKey(String ownerDot, String name, String desc) {
            this.ownerDot = ownerDot; this.name = name; this.desc = desc;
        }
        static MemberKey parse(String key) {
            int lastDot = key.lastIndexOf('.');
            String ownerDot = key.substring(0, lastDot);
            String rest = key.substring(lastDot + 1);
            int paren = rest.indexOf('(');
            if (paren < 0) return new MemberKey(ownerDot, rest, "");
            return new MemberKey(ownerDot, rest.substring(0, paren), rest.substring(paren));
        }
        /** Owner in JVM internal form ("com/example/Foo"). */
        String ownerInternal() { return internal(ownerDot); }
    }

    /** Internal-name owner of a renamed class, or the key's own owner if the class
     *  itself wasn't renamed. Used to point member mappings at the new class name. */
    static String renamedOwnerInternal(MemberKey mk, Map<String, Rename> classRenames) {
        Rename r = classRenames.get(mk.ownerDot);
        return r != null ? internal(r.name) : mk.ownerInternal();
    }

    static void writeSrgMapping(Map<String, Rename> classRenames,
                                 Map<String, Rename> fieldRenames,
                                 Map<String, Rename> methodRenames,
                                 File output) throws IOException {
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            classRenames.forEach((k, v) -> out.println("CL: " + internal(k) + " " + internal(v.name)));
            fieldRenames.forEach((k, v) -> {
                MemberKey mk = MemberKey.parse(k);
                String renamedOwner = renamedOwnerInternal(mk, classRenames);
                out.println("FD: " + mk.ownerInternal() + "/" + mk.name + " " + renamedOwner + "/" + v.name);
            });
            methodRenames.forEach((k, v) -> {
                MemberKey mk = MemberKey.parse(k);
                String renamedOwner = renamedOwnerInternal(mk, classRenames);
                out.println("MD: " + mk.ownerInternal() + "/" + mk.name + " " + mk.desc
                        + " " + renamedOwner + "/" + v.name + " " + mk.desc);
            });
        }
    }

    static void writeTinyMapping(Map<String, Rename> classRenames,
                                  Map<String, Rename> fieldRenames,
                                  Map<String, Rename> methodRenames,
                                  Map<String, String> fieldDescriptors,
                                  File output) throws IOException {
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.println("tiny\t2\t0\tofficial\tnamed");
            classRenames.forEach((k, v) -> out.println("CLASS\t" + internal(k) + "\t" + internal(v.name)));
            fieldRenames.forEach((k, v) -> {
                MemberKey mk = MemberKey.parse(k);
                // Tiny v2 requires the field descriptor between owner and source name.
                String desc = fieldDescriptors.getOrDefault(k, "Ljava/lang/Object;");
                out.println("FIELD\t" + mk.ownerInternal() + "\t" + desc + "\t" + mk.name + "\t" + v.name);
            });
            methodRenames.forEach((k, v) -> {
                MemberKey mk = MemberKey.parse(k);
                out.println("METHOD\t" + mk.ownerInternal() + "\t" + mk.desc + "\t" + mk.name + "\t" + v.name);
            });
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Scoring and classification ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    static double scoreString(String s) {
        if (s == null || s.length() < MIN_LEN || s.length() > MAX_LEN) return 0.0;
        String low = s.toLowerCase();

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â structural rejects (too short, too long, noise words)
        if (NOISE_WORDS.contains(low)) return 0.0;
        // Filter out noise segments (e.g. "DES/CBC/NoPadding" -> "NoPadding" noise)
        for (String segment : low.split("[/\\\\ ]")) {
            if (NOISE_WORDS.contains(segment)) return 0.0;
        }

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â pattern rejects (paths, crypto modes, Java properties, versions, FQCNs, base64, ciphertext)
        // Reject internal class name strings (slash-path format like "net/minecraft/Foo")
        if (s.contains("/") && SLASH_PATH.matcher(s).matches()) return 0.0;
        // Reject crypto algorithm strings ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â they appear in every encrypted class and are useless as names
        if (s.contains("/") && (low.contains("padding") || low.contains("pkcs") || low.contains("cbc")
                || low.contains("ecb") || low.contains("gcm") || low.contains("ofb"))) return 0.0;
        // Reject HTTP headers / MIME types ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â "text/html; charset=utf-8", "application/json"
        if (s.contains(";") && low.contains("charset")) return 0.0;
        if (s.contains("/") && (low.startsWith("text/") || low.startsWith("application/")
                || low.startsWith("image/") || low.startsWith("multipart/"))) return 0.0;
        // Reject Windows registry / file paths ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â "Control Panel\Desktop", "Software\Microsoft"
        if (s.contains("\\") && (low.contains("control panel") || low.contains("software\\")
                || low.contains("system\\") || low.contains("\\microsoft"))) return 0.0;
        // Reject Java property names
        if (s.startsWith("java.") || s.startsWith("javax.") || s.startsWith("sun.")) return 0.0;
        // Reject version strings like "1.8.0_202", "21.0.3"
        if (VERSION_STRING.matcher(s).matches()) return 0.0;
        // Reject fully-qualified class names: two or more lowercase-only dot-separated segments
        // (e.g. "net.minecraft.client.Minecraft") but allow mixed-case like "KillAura.Range"
        if (s.contains(".") && LOWER_FQCN.matcher(s).matches()) return 0.0;
        // Reject bare HTTP header names ("Content-Type", "Accept-Encoding", "X-Forwarded-For").
        // These match the pattern Word-Word and appear in any class doing HTTP but are useless as names.
        if (HTTP_HEADER_NAME.matcher(s).matches()) return 0.0;
        // Reject attribution / credit strings ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â "Developed by X", "Created by X", "Made by X".
        // The phrase "by " followed by a name is a developer credit, not a class name.
        if (low.startsWith("developed by ") || low.startsWith("created by ")
                || low.startsWith("made by ") || low.startsWith("coded by ")
                || low.startsWith("written by ")) return 0.0;
        // Reject strings containing & ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â typically "Alice & Bob" style credits or HTML entities.
        if (s.contains(" & ") || s.contains(" &amp;")) return 0.0;
        // Reject base64 alphabet / encoded data: long strings of only base64 chars
        if (s.length() >= 30) {
            boolean isBase64Alphabet = s.chars().allMatch(c ->
                    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_');
            if (isBase64Alphabet) return 0.0;
        }
        // Reject DES/XOR ciphertext: strings with control chars or non-printable bytes
        // leak through LDC as garbled text. Check for ctrl/high-byte density.
        {
            int ctrl = 0, highByte = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') ctrl++;
                else if (c > 0x7e) highByte++;
            }
            if (ctrl > 0 || highByte / (double) s.length() > 0.15) return 0.0;
        }

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â character composition scoring
        int letters = 0, digits = 0, special = 0, vowels = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetter(c)) {
                letters++;
                char lc = Character.toLowerCase(c);
                if (lc == 'a' || lc == 'e' || lc == 'i' || lc == 'o' || lc == 'u' || lc == 'y')
                    vowels++;
            } else if (Character.isDigit(c)) {
                digits++;
            } else if (c != ' ' && c != '_' && c != '-') {
                special++;
            }
        }

        int len = s.length();
        // Require a minimum vowel ratio in short strings ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â pure-consonant runs and
        // ciphertext tokens (e.g. "MzGIGb", "HeeGkb") typically have < 20% vowels.
        // Longer strings relax the threshold since they may be paths/identifiers with
        // underscore-separated segments where vowels are naturally diluted.
        if (letters > 0) {
            double vowelRatio = vowels / (double) letters;
            if (len < VOWEL_RATIO_MAX_LEN && vowelRatio < MIN_VOWEL_RATIO) return 0.0;
        }
        if (letters < 2 || special > Math.max(1, (int)(len * 0.20))) return 0.0;

        double score = letters / (double) len;

        // ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â bonus adjustments
        // Penalize all-caps strings including SCREAMING_SNAKE_CASE (constant/enum names).
        // The original check required letters==len to catch ALL_CAPS but missed names with
        // underscores. We now test the letters-only portion of the string.
        String lettersOnly = s.replaceAll("[^A-Za-z]", "");
        boolean isAllCaps = lettersOnly.length() > 0 && lettersOnly.equals(lettersOnly.toUpperCase());
        if (isAllCaps) score *= ALLCAPS_PENALTY;

        // Penalize version-string pattern: short word prefix followed by 1ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“3 trailing digits
        if (digits > 0 && letters >= 2) {
            String stripped = s.replaceAll("\\d+$", "");
            int trailingDigits = s.length() - stripped.length();
            if (trailingDigits >= 1 && trailingDigits <= 3 && stripped.length() <= 8)
                score -= 0.20;
        }

        if (Character.isUpperCase(s.charAt(0))) score += 0.15;
        for (int i = 1; i < len; i++)
            if (Character.isUpperCase(s.charAt(i)) && Character.isLowerCase(s.charAt(i - 1)))
                { score += 0.15; break; }
        if (s.indexOf('/') < 0 && s.indexOf('.') < 0 && s.indexOf(' ') < 0) score += 0.10;
        if (URL_PATTERN.matcher(s).matches()) return 0.90;
        if (len >= 4 && len <= 20 && letters == len && !isAllCaps) score += 0.20;

        return Math.min(score, 1.0);
    }

    static AnchorType classifyString(String s) {
        if (s == null) return AnchorType.NOISE;
        if (URL_PATTERN.matcher(s).matches())  return AnchorType.URL;
        if (PATH_PATTERN.matcher(s).find())    return AnchorType.PATH;
        if (IDENTIFIER.matcher(s).matches())   return AnchorType.IDENTIFIER;
        return AnchorType.NOISE;
    }

    static final Set<String> TLDS = new HashSet<>(Arrays.asList(
            "com", "net", "org", "io", "gg", "co", "uk", "dev", "app", "xyz",
            "me", "info", "cc", "tv", "ru", "de", "fr", "us", "biz", "online",
            "store", "site", "club", "live", "pro", "vip", "fun", "shop", "tech"));

    /** Reduces a URL to a single meaningful class-name token. Strips the scheme,
     *  path, query and a trailing TLD, then picks the most descriptive remaining
     *  host label (skipping generic prefixes like "www"/"api"/"cdn").
     *  e.g. https://discord.gg/abc -> "Discord", https://api.foo-bar.com -> "FooBar" */
    static String hostToName(String url) {
        String host = url.replaceAll("https?://", "").replaceAll("[/?#].*", "");
        if (host.isEmpty()) return null;
        String[] labels = host.split("\\.");
        int end = labels.length;
        if (end >= 2 && TLDS.contains(labels[end - 1].toLowerCase())) end--;          // drop TLD
        if (end >= 2 && TLDS.contains(labels[end - 1].toLowerCase())) end--;          // drop SLD TLD (co.uk)
        String chosen = null;
        for (int i = end - 1; i >= 0; i--) {                                          // prefer rightmost meaningful label
            String l = labels[i].toLowerCase();
            if (l.equals("www") || l.equals("api") || l.equals("cdn")
                    || l.equals("app") || l.equals("static") || l.isEmpty()) continue;
            chosen = labels[i];
            break;
        }
        if (chosen == null) chosen = labels[Math.max(0, end - 1)];
        return chosen.isEmpty() ? null : chosen;
    }

    static String sanitizeClassName(String raw) {
        if (raw == null) return null;
        // Convert multi-word strings to CamelCase ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â spaces mean a human-written feature/description.
        // Strategy depends on word count:
        //   1-3 words  ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ join all words  ("Kill Aura" ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ KillAura, "Box Mode" ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ BoxMode)
        //   4+ words   ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ take the LAST meaningful word only ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â description strings like
        //                "Shows Information And Usages About Other Commands" have their key
        //                noun at the end, not the beginning; taking the last word gives
        //                "Commands" rather than the awkward "ShowsInformationAnd".
        if (raw.contains(" ")) {
            String[] words = raw.split(" ");
            // Filter out empty and purely-punctuation tokens
            List<String> meaningful = new ArrayList<>();
            for (String w : words) {
                String stripped = w.replaceAll("[^A-Za-z0-9]", "");
                if (!stripped.isEmpty()) meaningful.add(w);
            }
            if (meaningful.isEmpty()) return null;
            if (meaningful.size() <= 3) {
                StringBuilder sb = new StringBuilder();
                for (String word : meaningful) {
                    if (!word.isEmpty())
                        sb.append(Character.toUpperCase(word.charAt(0))).append(word.substring(1));
                }
                raw = sb.toString();
            } else {
                // 4+ words: take the last meaningful word as the class name token
                String last = meaningful.get(meaningful.size() - 1);
                raw = Character.toUpperCase(last.charAt(0)) + last.substring(1);
            }
        }
        if (URL_PATTERN.matcher(raw).matches()) {
            String host = hostToName(raw);
            if (host == null) return null;
            raw = host;
        }
        // Take only the last segment of path-like strings (e.g. "rip/breeze/Client" -> "Client")
        if (raw.contains("/")) raw = raw.substring(raw.lastIndexOf('/') + 1);
        if (raw.contains("\\")) raw = raw.substring(raw.lastIndexOf('\\') + 1);

        String clean = raw.replaceAll("[^A-Za-z0-9_]", "_")
                          .replaceAll("_+", "_")
                          .replaceAll("^[^A-Za-z]+", "")
                          .replaceAll("[^A-Za-z0-9]+$", "");
        if (clean.isEmpty()) return null;
        if (clean.length() > MAX_LEN) clean = clean.substring(0, MAX_LEN);

        // Reject ciphertext: encrypted strings sanitize into names with very high
        // underscore density (e.g. "YZC_e_G_N_eFDJvGmL"). If more than 25% of the
        // sanitized name is underscores it's almost certainly not a real identifier.
        long underscores = clean.chars().filter(c -> c == '_').count();
        if (underscores > clean.length() * 0.25) return null;

        return Character.toUpperCase(clean.charAt(0)) + clean.substring(1);
    }

    static String sanitizeFieldName(String raw, AnchorType type) {
        if (raw == null || type == AnchorType.URL || type == AnchorType.PATH) return null;
        if (raw.contains("/")) raw = raw.substring(raw.lastIndexOf('/') + 1);
        String clean = raw.replaceAll("[^A-Za-z0-9_]", "_")
                          .replaceAll("_+", "_")
                          .replaceAll("^[^A-Za-z]+", "")
                          .replaceAll("[^A-Za-z0-9]+$", "");
        if (clean.length() < 2) return null;
        return Character.toLowerCase(clean.charAt(0)) + clean.substring(1);
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Utilities ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    /** Heuristic: does {@code name} already look like a meaningful identifier,
     *  so we should leave it alone? Tightened from the original (length&gt;3 +
     *  60% letters), which wrongly classified short obfuscator output like
     *  "abcd", "zzzz" or all-consonant runs as readable. We now additionally
     *  require length &ge; 4, a minimum vowel ratio of 20%, and that it is not a
     *  single repeated character ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â real words/camelCase names satisfy these,
     *  typical garbage identifiers do not. */
    static boolean isAlreadyReadable(String name) {
        if (name == null || name.length() < 4) return false;

        int letters = 0, vowels = 0;
        boolean hasNonRepeat = false;
        char first = name.charAt(0);
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isLetter(c)) letters++;
            char lc = Character.toLowerCase(c);
            if (lc == 'a' || lc == 'e' || lc == 'i' || lc == 'o' || lc == 'u' || lc == 'y') vowels++;
            if (c != first) hasNonRepeat = true;
        }
        if (letters / (double) name.length() <= 0.6) return false; // mostly non-letters ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ not a word
        if (vowels / (double) name.length() < MIN_VOWEL_RATIO) return false;
        return hasNonRepeat;
    }

    static String simpleClassName(String dotName) {
        int idx = dotName.lastIndexOf('.');
        return idx < 0 ? dotName : dotName.substring(idx + 1);
    }

    static String packageOf(String dotName) {
        int idx = dotName.lastIndexOf('.');
        return idx < 0 ? "" : dotName.substring(0, idx);
    }

    /** Binary name ("foo.Bar") ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ JVM internal name ("foo/Bar"). */
    static String internal(String dotName) { return dotName.replace('.', '/'); }

    /** JVM internal name ("foo/Bar") ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ binary name ("foo.Bar"). */
    static String binary(String slashName) { return slashName.replace('/', '.'); }

    /** Returns true if every segment of the package is short enough to be obfuscated
     *  (3 chars or fewer), AND the package has at least one segment (non-default).
     *  Excludes real short-but-legitimate roots by requiring ALL segments to be ÃƒÂ¢Ã¢â‚¬Â°Ã‚Â¤3 chars. */
    static boolean isObfuscatedPackage(String pkg) {
        if (pkg.isEmpty()) return false;
        String[] segments = pkg.split("\\.");
        // Require at least 2 segments to be short ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â single-segment packages like "net", "org", "com"
        // are legitimate root namespaces that also happen to be ÃƒÂ¢Ã¢â‚¬Â°Ã‚Â¤3 chars. Requiring a second short
        // segment (e.g. "net.a", "org.b") is a much stronger signal of obfuscation.
        if (segments.length < 2) return false;
        for (String segment : segments) {
            if (segment.length() > 3) return false; // has at least one meaningful segment
        }
        return true;
    }

    static String trueClassName(byte[] bytes, String entryPath) {
        try {
            return binary(new ClassReader(bytes).getClassName());
        } catch (Throwable t) {
            String raw = binary(entryPath);
            return raw.substring(0, raw.length() - 6);
        }
    }

    static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }

    static void loadLibraryClasses(File dir) {
        if (!dir.exists()) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) loadLibraryClasses(f);
            else if (f.getName().toLowerCase().endsWith(".jar")) {
                try (JarFile jar = new JarFile(f)) {
                    Enumeration<JarEntry> entries = jar.entries();
                    while (entries.hasMoreElements()) {
                        JarEntry entry = entries.nextElement();
                        if (entry.getName().endsWith(".class")) {
                            String name = binary(entry.getName());
                            libraryClasses.add(name.substring(0, name.length() - 6));
                        }
                    }
                } catch (Throwable ignored) {}
            }
        }
    }

    static void printUsage() {
        System.out.println("Usage: java -jar JarRemapper.jar [options] target.jar");
        System.out.println("Options:");
        System.out.println("  -out FILE      Output JAR path (default: <name>_remapped.jar)");
        System.out.println("  -map FILE      Mapping file path (default: <name>_mapping.txt)");
        System.out.println("  -strings FILE  Pre-decrypted strings from ENI_StringDumper all_strings.txt");
        System.out.println("  -decrypt       Attempt inline decryption by triggering <clinit> (UNSAFE)");
        System.out.println("  -decompile     Run CFR decompiler on output (requires cfr.jar in same dir)");
        System.out.println("  -dry           Dry run ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â compute renames but write no files");
        System.out.println("  -i             Interactive mode ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â prompt for low-confidence renames");
        System.out.println("  -libs DIR      Directory containing library JARs to ignore during renaming");
        System.out.println("  -srg FILE      Export mappings in SRG format");
        System.out.println("  -tiny FILE     Export mappings in Tiny v2 format");
        System.out.println("  -minlen N      Minimum string length (default 3)");
        System.out.println("  -maxlen N      Maximum string length (default 64)");
        System.out.println("  -score N       Minimum score 0.0-1.0 (default 0.55)");
        System.out.println("  -v             Verbose rename logging");
        System.out.println();
        System.out.println("Pipeline: java -jar JarRemapper.jar -libs libs/ -srg mappings.srg gothaj.jar");
    }

    /** Prompts for an interactive rename decision. Returns the chosen
     *  {@link Rename}, or {@code null} if the user skipped (meaning: keep the
     *  original name, add no mapping). The previous version fabricated a bogus
     *  rename to {@code simpleClassName(original)} on skip, which dropped the
     *  package for classes and produced nonsense for method keys. */
    static Rename promptUser(String original, Rename suggested, String reason) {
        System.out.print("[?] " + reason + ": " + original + " -> " + suggested.name + " (Enter to confirm, or type new name, or 's' to skip): ");
        String input = STDIN.nextLine().trim();
        if (input.isEmpty()) return suggested;
        if (input.equalsIgnoreCase("s")) return null;
        return new Rename(input, Confidence.HIGH); // User provided name is high confidence
    }

    enum AnchorType { IDENTIFIER, URL, PATH, FIELD_CONST, EXTERNAL, NOISE }
    enum Confidence { HIGH, MEDIUM, LOW }

    static class Rename {
        final String name;
        final Confidence confidence;
        Rename(String name, Confidence confidence) {
            this.name = name;
            this.confidence = confidence;
        }
    }

    static class StringAnchor {
        final String fieldName;
        final String value;
        final double score;
        final AnchorType type;

        StringAnchor(String fieldName, String value, double score, AnchorType type) {
            this.fieldName = fieldName;
            this.value     = value;
            this.score     = score;
            this.type      = type;
        }
    }
}
