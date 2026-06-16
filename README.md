# JarRemapper

Generic Java obfuscation remapper. Renames obfuscated classes and fields using string constants found in the bytecode as anchors. Works on any JAR without needing to know which obfuscator was used.

Part of the RE pipeline: **Memory Dump → Memory Carver → JAR → String Dumper → JarRemapper → Decompiler**

---

## How it works

1. Scans every class in the JAR for LDC string constants and field constant values
2. Scores each string by how readable it is (letter ratio, camelCase, length, URL patterns)
3. Penalises strings that appear in many classes — frequent strings make poor unique anchors
4. Renames each obfuscated class to its best unique anchor string
5. Rewrites all references throughout the entire JAR using ASM's ClassRemapper
6. Outputs a remapped JAR and a mapping file

The remapped JAR can then be fed into CFR or Procyon for much more readable decompiled output.

---

## Requirements

- Java 8+
- Nothing else — ASM is bundled in the JAR

---

## Run

```
java -jar JarRemapper.jar target.jar
```

Output goes next to the input JAR:
- `target_remapped.jar` — renamed, ready for decompilation
- `target_mapping.txt` — full list of every rename applied

---

## Options

| Flag | Description |
|------|-------------|
| `-out FILE` | Custom output JAR path |
| `-map FILE` | Custom mapping file path |
| `-minlen N` | Minimum string length to consider as anchor (default 3) |
| `-maxlen N` | Maximum string length to consider as anchor (default 64) |
| `-score N` | Minimum score threshold 0.0–1.0 (default 0.60) |
| `-v` | Verbose — print every rename decision |

---

## Limitations

- Only renames classes and fields — method renaming requires argument/return type analysis and is not yet implemented
- Quality of renames depends entirely on what readable strings exist in the bytecode. If strings are still encrypted (run the string dumper first to check), anchors will be limited
- Does not handle inner class rename propagation automatically
