//Exports program semantics (raw and high p-code, symbols, memory) for ppy-rev.
//@category ppy-rev
//@runtime Java

import com.google.gson.stream.JsonWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Headless post-script. Arguments: {@code output=<path>} and optionally
 * {@code decompile=true|false}, {@code decompile_timeout=<seconds>},
 * {@code max_block_bytes=<n>}.
 *
 * <p>This script only extracts. Normalization and every semantic decision happen in Python.
 */
public class PpyRevExport extends GhidraScript {
    private Program program;
    private JsonWriter json;
    private boolean decompile = true;
    private int decompileTimeout = 60;
    private long maxBlockBytes = 64L * 1024 * 1024;

    @Override
    protected void run() throws Exception {
        Path output = null;
        for (String arg : getScriptArgs()) {
            int eq = arg.indexOf('=');
            if (eq < 0) {
                throw new IllegalArgumentException("expected key=value argument, got " + arg);
            }
            String key = arg.substring(0, eq);
            String value = arg.substring(eq + 1);
            switch (key) {
                case "output" -> output = Path.of(value);
                case "decompile" -> decompile = Boolean.parseBoolean(value);
                case "decompile_timeout" -> decompileTimeout = Integer.parseInt(value);
                case "max_block_bytes" -> maxBlockBytes = Long.parseLong(value);
                default -> throw new IllegalArgumentException("unknown argument " + key);
            }
        }
        if (output == null) {
            throw new IllegalArgumentException("missing output=<path>");
        }
        program = currentProgram;
        Path partial = output.resolveSibling(output.getFileName() + ".partial");
        try (Writer writer = Files.newBufferedWriter(partial, StandardCharsets.UTF_8)) {
            json = new JsonWriter(writer);
            writeExport();
            json.flush();
        }
        Files.move(partial, output, StandardCopyOption.REPLACE_EXISTING,
            StandardCopyOption.ATOMIC_MOVE);
    }

    private void writeExport() throws Exception {
        json.beginObject();
        json.name("schema_version").value(ExportJson.SCHEMA_VERSION);
        json.name("producer");
        json.beginObject();
        json.name("ghidra_version").value(Application.getApplicationVersion());
        json.name("decompiled").value(decompile);
        json.endObject();
        writeBinary();
        writeAddressSpaces();
        writeRegisters();
        writeUserOps();
        writeMemoryBlocks();
        writeSymbols();
        writeStrings();
        writeExternalFunctions();
        writeFunctions();
        writeInstructions();
        json.endObject();
    }

    private void writeBinary() throws IOException {
        Language language = program.getLanguage();
        json.name("binary");
        json.beginObject();
        json.name("name").value(program.getName());
        ExportJson.nullableString(json, "format", program.getExecutableFormat());
        ExportJson.nullableString(json, "sha256", program.getExecutableSHA256());
        json.name("language").value(language.getLanguageID().getIdAsString());
        json.name("processor").value(language.getProcessor().toString());
        json.name("endianness").value(language.isBigEndian() ? "big" : "little");
        json.name("pointer_size").value(program.getDefaultPointerSize());
        json.name("compiler_spec").value(
            program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        json.name("image_base").value(ExportJson.hex(program.getImageBase().getOffset()));
        json.name("program_counter").value(language.getProgramCounter().getName());
        json.name("stack_pointer").value(
            program.getCompilerSpec().getStackPointer().getName());
        json.name("entry_points");
        json.beginArray();
        List<Address> entries = new ArrayList<>();
        Iterator<Address> entryIterator =
            program.getSymbolTable().getExternalEntryPointIterator();
        while (entryIterator.hasNext()) {
            entries.add(entryIterator.next());
        }
        entries.sort(Comparator.naturalOrder());
        for (Address entry : entries) {
            if (isLoaded(entry)) {
                json.value(ExportJson.hex(entry.getOffset()));
            }
        }
        json.endArray();
        json.endObject();
    }

    /** Addresses in the loaded program image, excluding file-only spaces such as .symtab. */
    private static boolean isLoaded(Address address) {
        return address.isMemoryAddress() && address.getAddressSpace().isLoadedMemorySpace();
    }

    private static String spaceKind(AddressSpace space) {
        return switch (space.getType()) {
            case AddressSpace.TYPE_CONSTANT -> "constant";
            case AddressSpace.TYPE_RAM, AddressSpace.TYPE_CODE -> "ram";
            case AddressSpace.TYPE_REGISTER -> "register";
            case AddressSpace.TYPE_UNIQUE -> "unique";
            case AddressSpace.TYPE_STACK -> "stack";
            case AddressSpace.TYPE_EXTERNAL -> "external";
            case AddressSpace.TYPE_VARIABLE -> "variable";
            default -> "other";
        };
    }

    private void writeAddressSpaces() throws IOException {
        json.name("address_spaces");
        json.beginArray();
        AddressSpace[] spaces = program.getAddressFactory().getAllAddressSpaces();
        Arrays.sort(spaces, Comparator.comparing(AddressSpace::getName));
        for (AddressSpace space : spaces) {
            json.beginObject();
            json.name("name").value(space.getName());
            json.name("kind").value(spaceKind(space));
            json.name("size").value(space.getSize() / 8);
            json.name("word_size").value(space.getAddressableUnitSize());
            json.endObject();
        }
        json.endArray();
    }

    private void writeRegisters() throws IOException {
        json.name("registers");
        json.beginArray();
        List<Register> registers = new ArrayList<>(program.getLanguage().getRegisters());
        registers.sort(Comparator.comparingInt(Register::getOffset)
            .thenComparing(Register::getBitLength, Comparator.reverseOrder())
            .thenComparing(Register::getName));
        for (Register register : registers) {
            if (register.isProcessorContext() || !register.getAddress().isRegisterAddress() ||
                register.getBitLength() % 8 != 0 || register.getLeastSignificantBit() != 0) {
                continue;
            }
            json.beginObject();
            json.name("name").value(register.getName());
            json.name("offset").value(ExportJson.hex(register.getOffset()));
            json.name("size").value(register.getMinimumByteSize());
            json.name("base").value(register.getBaseRegister().getName());
            json.endObject();
        }
        json.endArray();
    }

    private void writeUserOps() throws IOException {
        Language language = program.getLanguage();
        json.name("user_ops");
        json.beginArray();
        for (int i = 0; i < language.getNumberOfUserDefinedOpNames(); i++) {
            json.value(language.getUserDefinedOpName(i));
        }
        json.endArray();
    }

    private void writeMemoryBlocks() throws Exception {
        json.name("memory_blocks");
        json.beginArray();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            json.beginObject();
            json.name("name").value(block.getName());
            json.name("space").value(block.getStart().getAddressSpace().getName());
            json.name("start").value(ExportJson.hex(block.getStart().getOffset()));
            json.name("size").value(block.getSize());
            json.name("read").value(block.isRead());
            json.name("write").value(block.isWrite());
            json.name("execute").value(block.isExecute());
            json.name("initialized").value(block.isInitialized());
            json.name("loaded").value(block.isLoaded());
            json.name("external").value(block.isExternalBlock());
            json.name("artificial").value(block.isArtificial());
            boolean withBytes = block.isInitialized() && block.isLoaded() &&
                block.getStart().isMemoryAddress() && block.getSize() <= maxBlockBytes;
            json.name("bytes");
            if (withBytes) {
                byte[] bytes = new byte[(int) block.getSize()];
                int read = block.getBytes(block.getStart(), bytes);
                if (read != bytes.length) {
                    throw new IOException("short read from block " + block.getName());
                }
                json.value(ExportJson.base64(bytes));
            }
            else {
                json.nullValue();
            }
            json.endObject();
        }
        json.endArray();
    }

    private void writeSymbols() throws IOException {
        json.name("symbols");
        json.beginArray();
        SymbolIterator symbols = program.getSymbolTable().getAllSymbols(false);
        List<Symbol> sorted = new ArrayList<>();
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (isLoaded(symbol.getAddress()) || symbol.isExternal()) {
                sorted.add(symbol);
            }
        }
        sorted.sort(Comparator.comparing(Symbol::getAddress)
            .thenComparing(symbol -> symbol.getName()));
        for (Symbol symbol : sorted) {
            json.beginObject();
            json.name("name").value(symbol.getName());
            json.name("qualified_name").value(symbol.getName(true));
            json.name("kind").value(symbol.getSymbolType().toString());
            json.name("source").value(symbol.getSource().toString());
            json.name("external").value(symbol.isExternal());
            json.name("primary").value(symbol.isPrimary());
            json.name("entry_point").value(symbol.isExternalEntryPoint());
            json.name("address");
            if (isLoaded(symbol.getAddress())) {
                json.value(ExportJson.hex(symbol.getAddress().getOffset()));
            }
            else {
                json.nullValue();
            }
            json.endObject();
        }
        json.endArray();
    }

    private void writeStrings() throws Exception {
        json.name("strings");
        json.beginArray();
        for (Data data : DefinedStringIterator.forProgram(program)) {
            if (!isLoaded(data.getAddress())) {
                continue;
            }
            StringDataInstance string = StringDataInstance.getStringDataInstance(data);
            json.beginObject();
            json.name("address").value(ExportJson.hex(data.getAddress().getOffset()));
            json.name("length").value(data.getLength());
            ExportJson.nullableString(json, "value", string.getStringValue());
            ExportJson.nullableString(json, "charset", string.getCharsetName());
            json.name("bytes").value(ExportJson.bytesHex(data.getBytes()));
            json.name("references");
            writeReferencesTo(data.getAddress());
            json.endObject();
        }
        json.endArray();
    }

    private void writeReferencesTo(Address address) throws IOException {
        List<Reference> references = new ArrayList<>();
        for (Reference reference : program.getReferenceManager().getReferencesTo(address)) {
            if (isLoaded(reference.getFromAddress())) {
                references.add(reference);
            }
        }
        references.sort(Comparator.comparing(Reference::getFromAddress)
            .thenComparing(reference -> reference.getReferenceType().getName()));
        json.beginArray();
        for (Reference reference : references) {
            json.beginObject();
            json.name("from").value(ExportJson.hex(reference.getFromAddress().getOffset()));
            json.name("type").value(reference.getReferenceType().getName());
            json.endObject();
        }
        json.endArray();
    }

    private void writeExternalFunctions() throws IOException {
        json.name("external_functions");
        json.beginArray();
        List<Function> externals = new ArrayList<>();
        program.getFunctionManager().getExternalFunctions().forEach(externals::add);
        externals.sort(Comparator.comparing(Function::getEntryPoint));
        for (Function function : externals) {
            ExternalLocation location = function.getExternalLocation();
            json.beginObject();
            json.name("name").value(function.getName());
            json.name("external_address").value(
                ExportJson.hex(function.getEntryPoint().getOffset()));
            ExportJson.nullableString(json, "library",
                location == null ? null : location.getLibraryName());
            ExportJson.nullableString(json, "original_name",
                location == null ? null : location.getOriginalImportedName());
            json.name("no_return").value(function.hasNoReturn());
            json.name("signature").value(function.getPrototypeString(false, false));
            json.endObject();
        }
        json.endArray();
    }

    private void writeFunctions() throws Exception {
        DecompInterface decompiler = null;
        if (decompile) {
            decompiler = new DecompInterface();
            decompiler.toggleCCode(false);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(program)) {
                throw new IOException("decompiler failed to start: " +
                    decompiler.getLastMessage());
            }
        }
        try {
            json.name("functions");
            json.beginArray();
            for (Function function : program.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                writeFunction(function, decompiler);
            }
            json.endArray();
        }
        finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }
    }

    private void writeFunction(Function function, DecompInterface decompiler) throws Exception {
        json.beginObject();
        json.name("name").value(function.getName());
        json.name("entry").value(ExportJson.hex(function.getEntryPoint().getOffset()));
        json.name("no_return").value(function.hasNoReturn());
        json.name("calling_convention").value(function.getCallingConventionName());
        json.name("signature").value(function.getPrototypeString(false, false));
        json.name("signature_source").value(function.getSignatureSource().toString());
        json.name("varargs").value(function.hasVarArgs());
        json.name("thunk_target");
        Function thunked = function.isThunk() ? function.getThunkedFunction(true) : null;
        if (thunked == null) {
            json.nullValue();
        }
        else {
            json.beginObject();
            json.name("name").value(thunked.getName());
            json.name("external").value(thunked.isExternal());
            json.name("address").value(ExportJson.hex(thunked.getEntryPoint().getOffset()));
            json.endObject();
        }
        json.name("parameters");
        json.beginArray();
        for (Parameter parameter : function.getParameters()) {
            json.beginObject();
            json.name("name").value(parameter.getName());
            json.name("ordinal").value(parameter.getOrdinal());
            json.name("type").value(parameter.getDataType().getDisplayName());
            json.name("size").value(parameter.getLength());
            json.name("storage");
            writeStorage(parameter.getVariableStorage());
            json.endObject();
        }
        json.endArray();
        Parameter returned = function.getReturn();
        json.name("return");
        json.beginObject();
        json.name("type").value(returned.getDataType().getDisplayName());
        json.name("size").value(returned.getLength());
        json.name("storage");
        writeStorage(returned.getVariableStorage());
        json.endObject();
        json.name("body");
        json.beginArray();
        for (AddressRange range : function.getBody()) {
            json.beginArray();
            json.value(ExportJson.hex(range.getMinAddress().getOffset()));
            json.value(ExportJson.hex(range.getMaxAddress().getOffset()));
            json.endArray();
        }
        json.endArray();
        writeBlocks(function);
        json.name("high");
        if (decompiler == null || function.isThunk()) {
            json.nullValue();
        }
        else {
            writeHigh(function, decompiler);
        }
        json.endObject();
    }

    private void writeStorage(VariableStorage storage) throws IOException {
        json.beginArray();
        if (!storage.isBadStorage() && !storage.isUnassignedStorage()) {
            for (Varnode varnode : storage.getVarnodes()) {
                writeVarnode(varnode);
            }
        }
        json.endArray();
    }

    private void writeVarnode(Varnode varnode) throws IOException {
        ExportJson.varnode(json, varnode.getAddress().getAddressSpace().getName(),
            varnode.getOffset(), varnode.getSize());
    }

    private void writeBlocks(Function function) throws Exception {
        BasicBlockModel model = new BasicBlockModel(program);
        CodeBlockIterator blocks = model.getCodeBlocksContaining(function.getBody(), monitor);
        List<CodeBlock> sorted = new ArrayList<>();
        while (blocks.hasNext()) {
            sorted.add(blocks.next());
        }
        sorted.sort(Comparator.comparing(CodeBlock::getFirstStartAddress));
        json.name("blocks");
        json.beginArray();
        for (CodeBlock block : sorted) {
            json.beginObject();
            json.name("start").value(ExportJson.hex(block.getMinAddress().getOffset()));
            json.name("end").value(ExportJson.hex(block.getMaxAddress().getOffset()));
            List<Address> successors = new ArrayList<>();
            CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
            while (destinations.hasNext()) {
                CodeBlockReference destination = destinations.next();
                if (destination.getDestinationAddress().isMemoryAddress()) {
                    successors.add(destination.getDestinationAddress());
                }
            }
            successors.sort(Comparator.naturalOrder());
            json.name("successors");
            json.beginArray();
            for (Address successor : successors) {
                json.value(ExportJson.hex(successor.getOffset()));
            }
            json.endArray();
            json.endObject();
        }
        json.endArray();
    }

    private void writeHigh(Function function, DecompInterface decompiler) throws Exception {
        DecompileResults results =
            decompiler.decompileFunction(function, decompileTimeout, monitor);
        HighFunction high = results.getHighFunction();
        json.beginObject();
        if (high == null) {
            json.name("status").value(results.isTimedOut() ? "timeout" : "failed");
            ExportJson.nullableString(json, "error", results.getErrorMessage());
            json.endObject();
            return;
        }
        json.name("status").value("ok");
        FunctionPrototype prototype = high.getFunctionPrototype();
        json.name("prototype");
        json.beginObject();
        ExportJson.nullableString(json, "model", prototype.getModelName());
        json.name("return_type").value(prototype.getReturnType().getDisplayName());
        json.name("return_storage");
        writeStorage(prototype.getReturnStorage());
        json.name("varargs").value(prototype.isVarArg());
        json.name("no_return").value(prototype.hasNoReturn());
        json.name("parameters");
        json.beginArray();
        for (int i = 0; i < prototype.getNumParams(); i++) {
            writeHighSymbol(prototype.getParam(i));
        }
        json.endArray();
        json.endObject();

        List<HighSymbol> locals = new ArrayList<>();
        high.getLocalSymbolMap().getSymbols().forEachRemaining(locals::add);
        locals.sort(Comparator.comparing(HighSymbol::getName));
        json.name("symbols");
        json.beginArray();
        for (HighSymbol symbol : locals) {
            writeHighSymbol(symbol);
        }
        json.endArray();

        json.name("jump_tables");
        json.beginArray();
        for (JumpTable table : high.getJumpTables()) {
            json.beginObject();
            json.name("switch").value(ExportJson.hex(table.getSwitchAddress().getOffset()));
            json.name("cases");
            json.beginArray();
            for (Address target : table.getCases()) {
                json.value(ExportJson.hex(target.getOffset()));
            }
            json.endArray();
            json.name("labels");
            json.beginArray();
            for (Integer label : table.getLabelValues()) {
                json.value(label);
            }
            json.endArray();
            json.endObject();
        }
        json.endArray();

        writeHighBlocks(high);
        json.endObject();
    }

    private void writeHighSymbol(HighSymbol symbol) throws IOException {
        json.beginObject();
        json.name("name").value(symbol.getName());
        json.name("type").value(symbol.getDataType().getDisplayName());
        json.name("size").value(symbol.getSize());
        json.name("parameter").value(symbol.isParameter());
        json.name("storage");
        writeStorage(symbol.getStorage());
        json.endObject();
    }

    private void writeHighBlocks(HighFunction high) throws IOException {
        Map<Varnode, Integer> ids = new HashMap<>();
        json.name("blocks");
        json.beginArray();
        for (PcodeBlockBasic block : high.getBasicBlocks()) {
            json.beginObject();
            json.name("index").value(block.getIndex());
            json.name("start").value(ExportJson.hex(block.getStart().getOffset()));
            json.name("stop").value(ExportJson.hex(block.getStop().getOffset()));
            json.name("predecessors");
            json.beginArray();
            for (int i = 0; i < block.getInSize(); i++) {
                json.value(block.getIn(i).getIndex());
            }
            json.endArray();
            json.name("successors");
            json.beginArray();
            for (int i = 0; i < block.getOutSize(); i++) {
                json.value(block.getOut(i).getIndex());
            }
            json.endArray();
            json.name("ops");
            json.beginArray();
            Iterator<PcodeOp> ops = block.getIterator();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                json.beginObject();
                json.name("address").value(
                    ExportJson.hex(op.getSeqnum().getTarget().getOffset()));
                json.name("order").value(op.getSeqnum().getOrder());
                json.name("opcode").value(op.getMnemonic());
                json.name("inputs");
                json.beginArray();
                for (Varnode input : op.getInputs()) {
                    writeHighVarnode(input, ids);
                }
                json.endArray();
                json.name("output");
                if (op.getOutput() == null) {
                    json.nullValue();
                }
                else {
                    writeHighVarnode(op.getOutput(), ids);
                }
                writeOpSpaceAnnotations(op);
                json.endObject();
            }
            json.endArray();
            json.endObject();
        }
        json.endArray();
    }

    private void writeHighVarnode(Varnode varnode, Map<Varnode, Integer> ids) throws IOException {
        Integer id = ids.get(varnode);
        if (id == null) {
            id = ids.size();
            ids.put(varnode, id);
        }
        json.beginObject();
        json.name("id").value(id);
        json.name("space").value(varnode.getAddress().getAddressSpace().getName());
        json.name("offset").value(ExportJson.hex(varnode.getOffset()));
        json.name("size").value(varnode.getSize());
        HighVariable variable = varnode.getHigh();
        ExportJson.nullableString(json, "variable",
            variable == null ? null : variable.getName());
        json.endObject();
    }

    private void writeOpSpaceAnnotations(PcodeOp op) throws IOException {
        int opcode = op.getOpcode();
        if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
            AddressSpace space = program.getAddressFactory()
                .getAddressSpace((int) op.getInput(0).getOffset());
            ExportJson.nullableString(json, "memory_space",
                space == null ? null : space.getName());
        }
        else if (opcode == PcodeOp.CALLOTHER) {
            ExportJson.nullableString(json, "user_op", program.getLanguage()
                .getUserDefinedOpName((int) op.getInput(0).getOffset()));
        }
    }

    private void writeInstructions() throws Exception {
        json.name("instructions");
        json.beginArray();
        InstructionIterator instructions = program.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            json.beginObject();
            json.name("address").value(ExportJson.hex(instruction.getAddress().getOffset()));
            json.name("length").value(instruction.getLength());
            json.name("bytes").value(ExportJson.bytesHex(instruction.getBytes()));
            json.name("mnemonic").value(instruction.getMnemonicString());
            json.name("text").value(instruction.toString());
            json.name("flow").value(instruction.getFlowType().getName());
            Address fallthrough = instruction.getFallThrough();
            ExportJson.nullableString(json, "fallthrough",
                fallthrough == null ? null : ExportJson.hex(fallthrough.getOffset()));
            json.name("flows");
            json.beginArray();
            Address[] flows = instruction.getFlows();
            Arrays.sort(flows);
            for (Address flow : flows) {
                if (flow.isMemoryAddress()) {
                    json.value(ExportJson.hex(flow.getOffset()));
                }
            }
            json.endArray();
            json.name("references");
            json.beginArray();
            Reference[] references = instruction.getReferencesFrom();
            Arrays.sort(references, Comparator.comparing(Reference::getToAddress)
                .thenComparing(reference -> reference.getReferenceType().getName()));
            for (Reference reference : references) {
                Address to = reference.getToAddress();
                json.beginObject();
                json.name("to_space").value(to.getAddressSpace().getName());
                json.name("to").value(ExportJson.hex(to.getOffset()));
                json.name("type").value(reference.getReferenceType().getName());
                json.name("operand").value(reference.getOperandIndex());
                json.endObject();
            }
            json.endArray();
            json.name("pcode");
            json.beginArray();
            for (PcodeOp op : instruction.getPcode(false)) {
                json.beginObject();
                json.name("opcode").value(op.getMnemonic());
                json.name("inputs");
                json.beginArray();
                for (Varnode input : op.getInputs()) {
                    writeVarnode(input);
                }
                json.endArray();
                json.name("output");
                if (op.getOutput() == null) {
                    json.nullValue();
                }
                else {
                    writeVarnode(op.getOutput());
                }
                writeOpSpaceAnnotations(op);
                json.endObject();
            }
            json.endArray();
            json.endObject();
        }
        json.endArray();
    }
}
