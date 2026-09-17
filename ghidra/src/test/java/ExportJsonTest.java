import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gson.stream.JsonWriter;

import java.io.StringWriter;

import org.junit.jupiter.api.Test;

class ExportJsonTest {
    @Test
    void hexIsUnsignedLowercase() {
        assertEquals("0x0", ExportJson.hex(0));
        assertEquals("0x401136", ExportJson.hex(0x401136));
        assertEquals("0xffffffffffffffff", ExportJson.hex(-1));
        assertEquals("0x8000000000000000", ExportJson.hex(Long.MIN_VALUE));
    }

    @Test
    void bytesAreHexEncoded() {
        assertEquals("f30f1efa", ExportJson.bytesHex(new byte[] {(byte) 0xf3, 0x0f, 0x1e, (byte) 0xfa}));
        assertEquals("", ExportJson.bytesHex(new byte[0]));
    }

    @Test
    void varnodeIsCompactTriple() throws Exception {
        StringWriter out = new StringWriter();
        JsonWriter json = new JsonWriter(out);
        ExportJson.varnode(json, "register", 0x20, 8);
        json.flush();
        assertEquals("[\"register\",\"0x20\",8]", out.toString());
    }

    @Test
    void nullableStringWritesNull() throws Exception {
        StringWriter out = new StringWriter();
        JsonWriter json = new JsonWriter(out);
        json.beginObject();
        ExportJson.nullableString(json, "a", null);
        ExportJson.nullableString(json, "b", "x");
        json.endObject();
        json.flush();
        assertEquals("{\"a\":null,\"b\":\"x\"}", out.toString());
    }
}
