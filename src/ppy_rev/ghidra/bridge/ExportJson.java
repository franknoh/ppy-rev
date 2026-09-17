import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Formatting rules for the ppy-rev export schema. Kept free of Ghidra types so the
 * encoding can be unit tested without a Ghidra runtime.
 */
final class ExportJson {
    /** Bump whenever the meaning or shape of the export changes. */
    static final int SCHEMA_VERSION = 1;

    private ExportJson() {
    }

    /** Offsets and addresses are 64-bit unsigned quantities written as lowercase hex. */
    static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }

    static String bytesHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** A varnode is written compactly as {@code [space, offset, size]}. */
    static void varnode(JsonWriter json, String space, long offset, int size) throws IOException {
        json.beginArray();
        json.value(space);
        json.value(hex(offset));
        json.value(size);
        json.endArray();
    }

    static void nullableString(JsonWriter json, String name, String value) throws IOException {
        json.name(name);
        if (value == null) {
            json.nullValue();
        }
        else {
            json.value(value);
        }
    }
}
