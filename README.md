# JarRemapper

Java obfuscation remapper by elfasmedyje.

Renames obfuscated classes, fields, and methods using string constants found in the bytecode as naming anchors, then rewrites all references throughout the entire JAR using ASM's ClassRemapper. Handles Mixin-based clients, inner class hierarchies, enum constant detection, invokedynamic string tables, and structural classification when no string anchors are available.

---

## Requirements

- Java 8+
- `asm-9.x.jar` + `asm-commons-9.x.jar` to compile from source (both are bundled in the release JAR — not needed to run)

---

## Compile

```
javac -cp asm-9.8.jar;asm-commons-9.8.jar JarRemapper.java
```

On Linux/macOS use `:` instead of `;` in the classpath.

---

## Run

```
java -jar JarRemapper.jar [options] target.jar
```

Output goes next to the input JAR by default:
- `target_remapped.jar` — renamed, ready for decompilation
- `target_mapping.txt` — full list of every rename with confidence levels

---

## Options

| Flag | Description |
|------|-------------|
| `-out FILE` | Custom output JAR path |
| `-map FILE` | Custom mapping file path |
| `-strings FILE` | Pre-decrypted strings file from ENI_StringDumper — use a per-package `.log` file for attributed strings, or `all_strings.txt` for unattributed (half weight) |
| `-decrypt` | Attempt inline decryption by triggering `<clinit>` (unsafe, best-effort) |
| `-decompile` | Automatically run CFR decompiler on the output JAR |
| `-libs DIR` | Directory of library JARs to load for better class resolution |
| `-srg FILE` | Write an SRG-format mapping file |
| `-tiny FILE` | Write a Tiny v1 mapping file |
| `-minlen N` | Minimum string length to consider as anchor (default: 3) |
| `-maxlen N` | Maximum string length to consider as anchor (default: 64) |
| `-score N` | Minimum score threshold 0.0–1.0 (default: 0.55) |
| `-i` | Interactive mode — prompt before each rename decision |
| `-dry` | Dry run — print what would be renamed without writing any files |
| `-v` | Verbose — print every rename decision |

---

## Output

```
target_remapped.jar       renamed JAR, ready for CFR or Procyon
target_mapping.txt        full rename log with confidence levels
target_mapping.srg        SRG format (if -srg was passed)
target_mapping.tiny       Tiny v1 format (if -tiny was passed)
src/                      decompiled source (if -decompile was passed)
```

---

## Rename passes

Renames are applied in priority order. Higher passes only touch classes and members left unhandled by earlier ones.

| Pass | Source | Confidence |
|------|--------|------------|
| 0 | `@Shadow` field and method annotations — exact Minecraft names written by the developer | HIGH |
| 1 | `@Mixin(TargetClass.class)` annotation — class named `MixinTarget` | HIGH |
| 2 | String anchor scoring — best unique LDC/field/external string becomes the class name | HIGH (external) / MEDIUM (bytecode) |
| 2b | Field-only rename for classes that didn't receive a class rename | HIGH / MEDIUM |
| 2.5 | Exception/Error subclass detection — named `<Anchor>Exception` or `CustomException` | MEDIUM |
| 3 | Structural classification — `Consumer`, `Function`, `Listener`, `Manager`, `Utility`, `Vector2/3`, `Annotation` | LOW |
| 4 | Hierarchy propagation — subclasses named `<Super>_<Anchor>` or `<Super>_Impl` (fixpoint) | LOW |
| 5 | Inner class nesting — re-nested under renamed outer class as `Outer$Inner` | LOW |
| 6 | Method rename — descriptor shape and call-site context (`main`, `<clinit>`, `<init>`) | LOW |
| 7 | Package theming — obfuscated packages renamed using most common word across their renamed classes | MEDIUM / HIGH |

---

## Source tags in the mapping file

| Tag | Meaning |
|-----|---------|
| `[HIGH]` | Developer-written name (`@Shadow`, `@Mixin`) or runtime-decrypted string attributed to this class |
| `[MEDIUM]` | String anchor from bytecode LDC or field constant |
| `[LOW]` | Structural, hierarchy, or call-site guess |

---

## Example

```
java -jar JarRemapper.jar -strings dump/packages/com.example.log -decompile -v someobfuscated.jar
```
