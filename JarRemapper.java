import org.objectweb.asm.*;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.jar.*;
import java.util.regex.Pattern;

public class JarRemapper {

    static boolean VERBOSE   = false;
    static int     MIN_LEN   = 3;
    static int     MAX_LEN   = 64;
    static double  MIN_SCORE = 0.60;
    static String  OUT_JAR   = null;
    static String  OUT_MAP   = null;

    static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z][A-Za-z0-9_\\- ]{2,63}");
    static final Pattern URL_PATTERN = Pattern.compile("https?://[\\w./\\-?=&%]+");
    static final Pattern PATH_PATTERN = Pattern.compile("[a-zA-Z0-9_\\-]+[/\\\\][a-zA-Z0-9_\\-./\\\\]+");

    public static void main(String[] args) throws Exception {
        if (args.length < 1) { printUsage(); return; }

        List<String> positional = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-v":       VERBOSE   = true;                          break;
                case "-minlen":  MIN_LEN   = Integer.parseInt(args[++i]);   break;
                case "-maxlen":  MAX_LEN   = Integer.parseInt(args[++i]);   break;
                case "-score":   MIN_SCORE = Double.parseDouble(args[++i]); break;
                case "-out":     OUT_JAR   = args[++i];                     break;
                case "-map":     OUT_MAP   = args[++i];                     break;
                default:         positional.add(args[i]);                   break;
            }
        }

        if (positional.isEmpty()) { printUsage(); return; }

        File inputJar = new File(positional.get(0)).getAbsoluteFile();
        if (!inputJar.exists()) {
            System.err.println("[-] JAR not found: " + inputJar);
            return;
        }

        String base = inputJar.getName().replaceAll("\\.jar$", "");
        File outputJar = OUT_JAR != null ? new File(OUT_JAR)
                : new File(inputJar.getParentFile(), base + "_remapped.jar");
        File mapFile   = OUT_MAP != null ? new File(OUT_MAP)
                : new File(inputJar.getParentFile(), base + "_mapping.txt");

        System.out.println("[*] Input    : " + inputJar);
        System.out.println("[*] Output   : " + outputJar);
        System.out.println("[*] Mapping  : " + mapFile);
        System.out.println();

        Map<String, byte[]> classes    = new LinkedHashMap<>();
        Map<String, byte[]> resources  = new LinkedHashMap<>();

        try (JarFile jar = new JarFile(inputJar)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                byte[] data;
                try (InputStream is = jar.getInputStream(entry)) {
                    data = readAllBytes(is);
                }
                if (entry.getName().endsWith(".class"))
                    classes.put(entry.getName().replace('/', '.').replace(".class", ""), data);
                else if (!entry.isDirectory())
                    resources.put(entry.getName(), data);
            }
        }

        System.out.println("[+] Loaded " + classes.size() + " classes, " + resources.size() + " resources.");

        System.out.println("[*] Extracting string anchors...");
        Map<String, List<StringAnchor>> anchors = extractAnchors(classes);
        System.out.println("[+] Found anchors in " + anchors.size() + " classes.");

        System.out.println("[*] Building rename map...");
        Map<String, String> classRenames  = new LinkedHashMap<>();
        Map<String, String> fieldRenames  = new LinkedHashMap<>();
        buildRenameMap(classes, anchors, classRenames, fieldRenames);
        System.out.println("[+] " + classRenames.size() + " classes to rename, "
                + fieldRenames.size() + " fields to rename.");

        if (classRenames.isEmpty() && fieldRenames.isEmpty()) {
            System.out.println("[!] Nothing to rename — JAR may not be obfuscated or strings aren't useful anchors.");
            return;
        }

        System.out.println("[*] Applying renames and writing output JAR...");
        writeRemappedJar(classes, resources, classRenames, fieldRenames, outputJar);
        writeMappingFile(classRenames, fieldRenames, mapFile);

        System.out.println();
        System.out.println("  Done.");
        System.out.printf("  %-22s %d classes%n",  "Classes renamed:", classRenames.size());
        System.out.printf("  %-22s %d fields%n",   "Fields renamed:",  fieldRenames.size());
        System.out.println("  Output JAR : " + outputJar.getAbsolutePath());
        System.out.println("  Mapping    : " + mapFile.getAbsolutePath());
    }

    static Map<String, List<StringAnchor>> extractAnchors(Map<String, byte[]> classes) {
        Map<String, List<StringAnchor>> result = new LinkedHashMap<>();

        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            String className = e.getKey();
            List<StringAnchor> anchors = new ArrayList<>();

            try {
                new ClassReader(e.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
                    String currentField = null;

                    @Override
                    public FieldVisitor visitField(int access, String name, String descriptor,
                                                    String signature, Object value) {
                        currentField = name;
                        if (value instanceof String) {
                            String s = (String) value;
                            anchors.add(new StringAnchor(name, s, scoreString(s), AnchorType.FIELD_CONST));
                        }
                        return super.visitField(access, name, descriptor, signature, value);
                    }

                    @Override
                    public MethodVisitor visitMethod(int access, String mname, String descriptor,
                                                     String signature, String[] exceptions) {
                        return new MethodVisitor(Opcodes.ASM9) {
                            String lastField = null;

                            @Override
                            public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                                if (opcode == Opcodes.PUTSTATIC || opcode == Opcodes.PUTFIELD)
                                    lastField = fname;
                                else
                                    lastField = null;
                            }

                            @Override
                            public void visitLdcInsn(Object cst) {
                                if (!(cst instanceof String)) return;
                                String s = (String) cst;
                                double score = scoreString(s);
                                AnchorType type = classifyString(s);
                                anchors.add(new StringAnchor(lastField, s, score, type));
                                lastField = null;
                            }

                            @Override
                            public void visitInsn(int opcode) { lastField = null; }
                        };
                    }
                }, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
            } catch (Throwable ignored) {}

            if (!anchors.isEmpty())
                result.put(className, anchors);
        }
        return result;
    }

    static void buildRenameMap(Map<String, byte[]> classes,
                                Map<String, List<StringAnchor>> anchors,
                                Map<String, String> classRenames,
                                Map<String, String> fieldRenames) {
        // Count how many classes each string value appears in — frequent strings make poor anchors
        Map<String, Integer> stringFrequency = new HashMap<>();
        for (List<StringAnchor> list : anchors.values())
            for (StringAnchor a : list)
                stringFrequency.merge(a.value, 1, Integer::sum);

        Set<String> usedClassNames = new HashSet<>();
        Set<String> existingNames  = new HashSet<>(classes.keySet());
        Map<String, Integer> nameCollisionCount = new HashMap<>();

        for (Map.Entry<String, List<StringAnchor>> e : anchors.entrySet()) {
            String originalClass = e.getKey();
            List<StringAnchor> classAnchors = e.getValue();

            String simpleClass = simpleClassName(originalClass);
            if (isAlreadyReadable(simpleClass)) continue;

            StringAnchor best = null;
            double bestScore = -1;
            for (StringAnchor a : classAnchors) {
                if (a.score < MIN_SCORE) continue;
                if (a.type == AnchorType.NOISE) continue;
                int freq = stringFrequency.getOrDefault(a.value, 1);
                double adjustedScore = a.score / Math.sqrt(freq);
                if (adjustedScore > bestScore) {
                    bestScore = adjustedScore;
                    best = a;
                }
            }

            if (best == null) continue;

            String proposed = sanitizeClassName(best.value);
            if (proposed == null || proposed.isEmpty()) continue;

            String pkg = packageOf(originalClass);
            String base = pkg.isEmpty() ? proposed : pkg + "." + proposed;
            String fullProposed = base;

            if (existingNames.contains(fullProposed) || usedClassNames.contains(fullProposed)) {
                int n = nameCollisionCount.merge(base, 1, Integer::sum);
                fullProposed = base + "_" + n;
            }

            classRenames.put(originalClass, fullProposed);
            usedClassNames.add(fullProposed);

            int freq = stringFrequency.getOrDefault(best.value, 1);
            if (VERBOSE)
                System.out.println("  CLASS  " + simpleClass + " -> " + simpleClassName(fullProposed)
                        + "  (\"" + best.value + "\" score=" + String.format("%.2f", best.score)
                        + " freq=" + freq + ")");

            for (StringAnchor a : classAnchors) {
                if (a.fieldName == null || a.score < MIN_SCORE) continue;
                if (isAlreadyReadable(a.fieldName)) continue;
                String fProposed = sanitizeFieldName(a.value, a.type);
                if (fProposed == null) continue;
                String fKey = originalClass + "." + a.fieldName;
                if (!fieldRenames.containsKey(fKey)) {
                    fieldRenames.put(fKey, fProposed);
                    if (VERBOSE)
                        System.out.println("  FIELD  " + a.fieldName + " -> " + fProposed
                                + "  (\"" + a.value + "\")");
                }
            }
        }
    }

    static void writeRemappedJar(Map<String, byte[]> classes,
                                  Map<String, byte[]> resources,
                                  Map<String, String> classRenames,
                                  Map<String, String> fieldRenames,
                                  File outputJar) throws IOException {
        Map<String, String> internalRenames = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : classRenames.entrySet())
            internalRenames.put(e.getKey().replace('.', '/'), e.getValue().replace('.', '/'));

        Remapper remapper = new Remapper() {
            @Override
            public String map(String internalName) {
                return internalRenames.getOrDefault(internalName, internalName);
            }

            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                String key = owner.replace('/', '.') + "." + name;
                return fieldRenames.getOrDefault(key, name);
            }
        };

        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(outputJar))) {
            for (Map.Entry<String, byte[]> e : classes.entrySet()) {
                String originalDotName = e.getKey();
                byte[] originalBytes   = e.getValue();

                byte[] remapped;
                try {
                    ClassReader cr = new ClassReader(originalBytes);
                    ClassWriter cw = new ClassWriter(cr, 0);
                    cr.accept(new ClassRemapper(cw, remapper), ClassReader.EXPAND_FRAMES);
                    remapped = cw.toByteArray();
                } catch (Throwable t) {
                    remapped = originalBytes;
                }

                String newDotName = classRenames.getOrDefault(originalDotName, originalDotName);
                String entryName  = newDotName.replace('.', '/') + ".class";

                jos.putNextEntry(new JarEntry(entryName));
                jos.write(remapped);
                jos.closeEntry();
            }

            for (Map.Entry<String, byte[]> e : resources.entrySet()) {
                if (e.getKey().equals("META-INF/MANIFEST.MF")) continue;
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

    static void writeMappingFile(Map<String, String> classRenames,
                                  Map<String, String> fieldRenames,
                                  File mapFile) throws IOException {
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(mapFile), StandardCharsets.UTF_8))) {
            out.println("# JarRemapper mapping file");
            out.println("# Format: TYPE original -> renamed");
            out.println();
            for (Map.Entry<String, String> e : classRenames.entrySet())
                out.println("CLASS " + e.getKey() + " -> " + e.getValue());
            out.println();
            for (Map.Entry<String, String> e : fieldRenames.entrySet())
                out.println("FIELD " + e.getKey() + " -> " + e.getValue());
        }
    }

    static double scoreString(String s) {
        if (s == null || s.length() < MIN_LEN || s.length() > MAX_LEN) return 0.0;

        int letters = 0, digits = 0, spaces = 0, special = 0;
        for (char c : s.toCharArray()) {
            if (Character.isLetter(c)) letters++;
            else if (Character.isDigit(c)) digits++;
            else if (c == ' ' || c == '_' || c == '-') spaces++;
            else special++;
        }

        int len = s.length();
        if (letters < 2) return 0.0;
        if (special > len * 0.3) return 0.0;

        double letterRatio = letters / (double) len;
        double score = letterRatio;

        if (Character.isUpperCase(s.charAt(0))) score += 0.15;
        boolean camel = false;
        for (int i = 1; i < s.length(); i++) {
            if (Character.isUpperCase(s.charAt(i)) && Character.isLowerCase(s.charAt(i - 1))) {
                camel = true; break;
            }
        }
        if (camel) score += 0.15;
        if (!s.contains(" ") && !s.contains("/") && !s.contains(".")) score += 0.10;
        if (URL_PATTERN.matcher(s).matches()) score = 0.90;
        if (s.length() >= 4 && s.length() <= 20 && letters == len) score += 0.20;

        return Math.min(score, 1.0);
    }

    static AnchorType classifyString(String s) {
        if (s == null) return AnchorType.NOISE;
        if (URL_PATTERN.matcher(s).matches()) return AnchorType.URL;
        if (PATH_PATTERN.matcher(s).find())   return AnchorType.PATH;
        if (s.length() >= 3 && s.length() <= 30 && IDENTIFIER.matcher(s).matches())
            return AnchorType.IDENTIFIER;
        return AnchorType.NOISE;
    }

    static String sanitizeClassName(String raw) {
        if (raw == null) return null;
        if (URL_PATTERN.matcher(raw).matches()) {
            String host = raw.replaceAll("https?://", "").replaceAll("[/\\?#].*", "");
            return toClassName(host.replace('.', '_'));
        }
        String clean = raw.replaceAll("[^A-Za-z0-9_]", "_").replaceAll("_+", "_");
        clean = clean.replaceAll("^[^A-Za-z]+", "").replaceAll("[^A-Za-z0-9]+$", "");
        if (clean.isEmpty()) return null;
        return Character.toUpperCase(clean.charAt(0)) + clean.substring(1);
    }

    static String sanitizeFieldName(String raw, AnchorType type) {
        if (raw == null) return null;
        if (type == AnchorType.URL) return "serverUrl";
        if (type == AnchorType.PATH) return "filePath";
        String clean = raw.replaceAll("[^A-Za-z0-9_]", "_").replaceAll("_+", "_");
        clean = clean.replaceAll("^[^A-Za-z]+", "").replaceAll("[^A-Za-z0-9]+$", "");
        if (clean.isEmpty() || clean.length() < 2) return null;
        return Character.toLowerCase(clean.charAt(0)) + clean.substring(1);
    }

    static String toClassName(String s) {
        if (s == null || s.isEmpty()) return null;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    static boolean isAlreadyReadable(String name) {
        if (name == null || name.length() <= 2) return false;
        int letters = 0;
        for (char c : name.toCharArray()) if (Character.isLetter(c)) letters++;
        return letters / (double) name.length() > 0.6 && name.length() > 3;
    }

    static String simpleClassName(String dotName) {
        int idx = dotName.lastIndexOf('.');
        return idx < 0 ? dotName : dotName.substring(idx + 1);
    }

    static String packageOf(String dotName) {
        int idx = dotName.lastIndexOf('.');
        return idx < 0 ? "" : dotName.substring(0, idx);
    }

    static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }

    static void printUsage() {
        System.out.println("Usage: java -jar JarRemapper.jar [options] target.jar");
        System.out.println("Options:");
        System.out.println("  -out FILE    Output JAR path (default: <name>_remapped.jar)");
        System.out.println("  -map FILE    Mapping file path (default: <name>_mapping.txt)");
        System.out.println("  -minlen N    Minimum string length to consider (default 3)");
        System.out.println("  -maxlen N    Maximum string length to consider (default 64)");
        System.out.println("  -score N     Minimum score threshold 0.0-1.0 (default 0.60)");
        System.out.println("  -v           Verbose rename logging");
    }

    enum AnchorType { IDENTIFIER, URL, PATH, FIELD_CONST, NOISE }

    static class StringAnchor {
        final String     fieldName;
        final String     value;
        final double     score;
        final AnchorType type;

        StringAnchor(String fieldName, String value, double score, AnchorType type) {
            this.fieldName = fieldName;
            this.value     = value;
            this.score     = score;
            this.type      = type;
        }
    }
}
