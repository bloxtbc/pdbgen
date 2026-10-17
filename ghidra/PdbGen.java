//Generates a PDB containing public symbols and type information derived from ghidra's database
//@author Brett Wandel
//@category Windows
//@keybinding ctrl G
//@menupath Tools.Generate PDB
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FilenameUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import generic.util.Path;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.app.util.bin.format.pe.FileHeader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.framework.options.Options;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import pdb.PdbPlugin;
import pdb.symbolserver.SymbolFileInfo;
import pdb.symbolserver.SymbolServerInstanceCreatorContext;
import pdb.symbolserver.SymbolServerInstanceCreatorRegistry;
import pdb.symbolserver.SymbolServerService;
import pdb.symbolserver.SymbolStore;

public class PdbGen extends GhidraScript {
	public final static String PREFERENCE_SYMBOL_OUTPUT_PATH = "PDBGEN_SYMBOL_OUTPUT_PATH";
	public final static String OVERRIDE_SYMBOL_OUTPUT_PATH = null;
	// Note: we are manually serializing json here, this is just to avoid any dependencies.
	// this means it will break if we have any fields that need escaping.
	Map<String, String> typedefs = new HashMap<String, String>();
	Set<String> serialized = new HashSet<String>();
	Map<String, String> forwardDeclared = new HashMap<String, String>();

	Map<Address, FunctionDefinition> entrypoints = new HashMap<Address, FunctionDefinition>();
	Map<Address, Function> exportableFunctions = new HashMap<Address, Function>();
	private FilterConfiguration filterConfiguration = new FilterConfiguration();
	private final FilterStatistics filterStatistics = new FilterStatistics();
	private String pdbgenExecutable = "pdbgen.exe";

	private static final String[] UNWIND_PREFIXES = {
		"unwind@", "__unwind", "__ehunwind", "__ehhandler$"
	};

	// Match reserved runtime spellings and standard-library namespaces, not generic
	// compiler-looking names or short functions; custom allocators remain eligible.
	private static final String[] RUNTIME_PREFIXES = {
		"__cxxframehandler", "___cxxframehandler", "_cxxthrowexception",
		"__cxxthrowexception", "_eh", "__eh", "_rtc", "__rtc",
		"_security_", "__security_", "___security_", "__gs",
		"___gs", "__guard_", "__report_gsfailure", "_except_handler",
		"__except_handler", "_c_specific_handler", "__c_specific_handler",
		"___c_specific_handler", "__cxxregisterexceptionobject",
		"__cxxdetectrethrow", "__cxxunregisterexceptionobject",
		"_delayloadhelper", "__delayloadhelper",
		"__funloaddelayloadeddll", "??_r", "??_7type_info",
		"??_gtype_info"
	};

	private static final String[] CRT_FUNCTION_NAMES = {
		"memcpy", "memmove", "memset", "memcmp", "strlen", "strcpy",
		"strncpy", "strcat", "strcmp", "strncmp", "malloc", "calloc",
		"realloc", "free", "printf", "sprintf", "vsprintf"
	};

	private static final String[] COMPILER_FUNCTION_PREFIXES = {
		"__chkstk", "___chkstk", "_chkstk", "__alloca_probe",
		"_alloca_probe", "__allmul", "__alldiv", "__aulldiv",
		"__allrem", "__aullrem", "__allshl", "__allshr", "__aullshr",
		"__ftol"
	};

	private static class FilterConfiguration {
		boolean excludeRuntime = true;
		boolean excludeUnwind = true;
		boolean excludeThunks = true;
		boolean excludeCompiler = true;
		boolean excludeNonExecutable = false;
		boolean verbose = false;
	}

	private static class FilterStatistics {
		int discovered;
		int exported;
		int unwindSkipped;
		int runtimeSkipped;
		int importThunksSkipped;
		int compilerSkipped;
		int nonExecutableSkipped;
		int externalSkipped;
		int typeRecords;
		int symbolRecords;
		long startNanos;
		final Map<String, List<String>> examples = new HashMap<String, List<String>>();

		void record(String category, String name) {
			List<String> names = examples.get(category);
			if (names == null) {
				names = new ArrayList<String>();
				examples.put(category, names);
			}
			if (names.size() < 10) {
				names.add(name);
			}
		}
	}

	private void configureFiltering() {
		filterConfiguration = new FilterConfiguration();
		String configuredExecutable = System.getenv("PDBGEN_EXE");
		pdbgenExecutable = configuredExecutable == null || configuredExecutable.isEmpty() ?
			"pdbgen.exe" : configuredExecutable;
		String[] arguments = getScriptArgs();
		for (int i = 0; i < arguments.length; i++) {
			String argument = arguments[i];
			if ("--exclude-runtime".equals(argument)) {
				filterConfiguration.excludeRuntime = true;
			} else if ("--include-runtime".equals(argument)) {
				filterConfiguration.excludeRuntime = false;
			} else if ("--exclude-unwind".equals(argument)) {
				filterConfiguration.excludeUnwind = true;
			} else if ("--include-unwind".equals(argument)) {
				filterConfiguration.excludeUnwind = false;
			} else if ("--exclude-thunks".equals(argument)) {
				filterConfiguration.excludeThunks = true;
			} else if ("--include-thunks".equals(argument)) {
				filterConfiguration.excludeThunks = false;
			} else if ("--exclude-compiler".equals(argument)) {
				filterConfiguration.excludeCompiler = true;
			} else if ("--include-compiler".equals(argument)) {
				filterConfiguration.excludeCompiler = false;
			} else if ("--exclude-non-executable".equals(argument)) {
				filterConfiguration.excludeNonExecutable = true;
			} else if ("--include-non-executable".equals(argument)) {
				filterConfiguration.excludeNonExecutable = false;
			} else if ("--verbose-filtering".equals(argument)) {
				filterConfiguration.verbose = true;
			} else if ("--pdbgen-exe".equals(argument)) {
				if (++i >= arguments.length || arguments[i].isEmpty()) {
					throw new IllegalArgumentException("--pdbgen-exe requires a path");
				}
				pdbgenExecutable = arguments[i];
			} else if (argument.startsWith("--pdbgen-exe=")) {
				pdbgenExecutable = argument.substring("--pdbgen-exe=".length());
				if (pdbgenExecutable.isEmpty()) {
					throw new IllegalArgumentException("--pdbgen-exe requires a path");
				}
			} else {
				throw new IllegalArgumentException("Unknown PdbGen option: " + argument);
			}
		}
	}

	private String normalizedFunctionName(String name) {
		String normalized = name;
		while (normalized.startsWith("FID_conflict:")) {
			normalized = normalized.substring("FID_conflict:".length());
		}
		if (normalized.startsWith("thunk_")) {
			normalized = normalized.substring("thunk_".length());
		}
		return normalized;
	}

	private boolean startsWithAny(String value, String[] prefixes) {
		for (String prefix : prefixes) {
			if (value.startsWith(prefix)) {
				return true;
			}
		}
		return false;
	}

	private boolean isUnwindFunction(String name) {
		String normalized = normalizedFunctionName(name).toLowerCase(Locale.ROOT);
		return startsWithAny(normalized, UNWIND_PREFIXES);
	}

	private boolean isVisualStudioRuntimeFunction(String name) {
		String normalized = normalizedFunctionName(name).toLowerCase(Locale.ROOT);
		if (normalized.startsWith("scimitar::")) {
			return false;
		}
		if (normalized.startsWith("std::") || normalized.startsWith("stdext::") ||
			normalized.startsWith("type_info::")) {
			return true;
		}
		if (startsWithAny(normalized, RUNTIME_PREFIXES)) {
			return true;
		}
		if (normalized.indexOf("::") < 0) {
			for (String functionName : CRT_FUNCTION_NAMES) {
				if (normalized.equals(functionName) || normalized.equals("_" + functionName)) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean isCompilerGeneratedFunction(String name) {
		String normalized = normalizedFunctionName(name).toLowerCase(Locale.ROOT);
		return startsWithAny(normalized, COMPILER_FUNCTION_PREFIXES);
	}

	private boolean isImportThunk(Function function) {
		// An external destination is definitive import evidence; other thunks need
		// a separately recognized runtime destination before they can be removed.
		if (!function.isThunk()) {
			return false;
		}
		Function target = function.getThunkedFunction(false);
		return target != null && target.isExternal();
	}

	private boolean isTrivialThunk(Function function) {
		if (!function.isThunk()) {
			return false;
		}
		Function target = function.getThunkedFunction(false);
		return target != null &&
			(isVisualStudioRuntimeFunction(target.getName(true)) ||
			 isCompilerGeneratedFunction(target.getName(true)));
	}

	private String getFunctionFilterReason(Function function) {
		if (function.isExternal()) {
			return "external";
		}
		String name = function.getName(true);
		if (filterConfiguration.excludeUnwind && isUnwindFunction(name)) {
			return "unwind";
		}
		if (filterConfiguration.excludeRuntime && isVisualStudioRuntimeFunction(name)) {
			return "runtime";
		}
		if (filterConfiguration.excludeThunks &&
			(isImportThunk(function) || isTrivialThunk(function))) {
			return "import thunk";
		}
		if (filterConfiguration.excludeCompiler && isCompilerGeneratedFunction(name)) {
			return "compiler";
		}
		if (filterConfiguration.excludeNonExecutable) {
			MemoryBlock block = currentProgram.getMemory().getBlock(function.getEntryPoint());
			if (block != null && !block.isExecute()) {
				return "non-executable";
			}
		}
		return null;
	}

	private boolean shouldExportFunction(Function function) {
		String reason = getFunctionFilterReason(function);
		if (reason == null) {
			return true;
		}
		switch (reason) {
			case "unwind":
				filterStatistics.unwindSkipped++;
				break;
			case "runtime":
				filterStatistics.runtimeSkipped++;
				break;
			case "import thunk":
				filterStatistics.importThunksSkipped++;
				break;
			case "compiler":
				filterStatistics.compilerSkipped++;
				break;
			case "non-executable":
				filterStatistics.nonExecutableSkipped++;
				break;
			case "external":
				filterStatistics.externalSkipped++;
				break;
			default:
				throw new IllegalStateException("Unknown function filter category: " + reason);
		}
		if (filterConfiguration.verbose) {
			filterStatistics.record(reason, function.getName(true));
		}
		return false;
	}

	private void discoverFunctions() {
		FunctionManager manager = currentProgram.getFunctionManager();
		Iterator<Function> functions = manager.getFunctionsNoStubs(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			filterStatistics.discovered++;
			if (!shouldExportFunction(function)) {
				continue;
			}
			Address entry = function.getEntryPoint();
			exportableFunctions.put(entry, function);
			filterStatistics.exported++;
			if (!function.isThunk()) {
				FunctionSignature signature = function.getSignature();
				if (signature instanceof FunctionDefinition) {
					entrypoints.put(entry, (FunctionDefinition) signature);
				}
			}
		}
	}

	private void printFilterStatistics(String jsonPath) {
		int filtered = filterStatistics.discovered - filterStatistics.exported;
		double reduction = filterStatistics.discovered == 0 ? 0.0 :
			100.0 * filtered / filterStatistics.discovered;
		printf("[PDBGEN] Functions discovered:       %d\n", filterStatistics.discovered);
		printf("[PDBGEN] Functions exported:         %d\n", filterStatistics.exported);
		printf("[PDBGEN] Unwind functions skipped:   %d\n", filterStatistics.unwindSkipped);
		printf("[PDBGEN] MSVC/runtime skipped:       %d\n", filterStatistics.runtimeSkipped);
		printf("[PDBGEN] Import thunks skipped:      %d\n", filterStatistics.importThunksSkipped);
		printf("[PDBGEN] Other compiler functions:   %d\n", filterStatistics.compilerSkipped);
		printf("[PDBGEN] Non-executable skipped:     %d\n", filterStatistics.nonExecutableSkipped);
		printf("[PDBGEN] External functions skipped: %d\n", filterStatistics.externalSkipped);
		printf("[PDBGEN] Function reduction:         %.2f%%\n", reduction);
		printf("[PDBGEN] Type records exported:      %d\n", filterStatistics.typeRecords);
		printf("[PDBGEN] Symbol records exported:    %d\n", filterStatistics.symbolRecords);
		printf("[PDBGEN] JSON size:                  %d bytes\n",
			new File(jsonPath).length());
		printf("[PDBGEN] Export elapsed:             %.2f seconds\n",
			(System.nanoTime() - filterStatistics.startNanos) / 1000000000.0);
		if (filterConfiguration.verbose) {
			for (Map.Entry<String, List<String>> entry : filterStatistics.examples.entrySet()) {
				for (String name : entry.getValue()) {
					printf("[filter] %-40s -> %s\n", name, entry.getKey());
				}
			}
		}
	}

	private boolean isSerialized(DataType dt) {
		String id = GetId(dt);
		return isSerialized(id);
	}

	private boolean isSerialized(String id) {
		return serialized.contains(id);
	}

	private void setSerialized(DataType dt) {
		String id = GetId(dt);
		serialized.add(id);
	}

	private String GetIdUnmapped(DataType dt) {
		if (dt == null) {
			// Not sure if this should be LF_NULLLEAF (0x0009)
			// using no type (0x0000) first, this might need to change
			return "0x0000"; // uncharacterized type (no type)
		}

		// FML... this needs to be fixed at some point.
		String name = dt.getPathName();
//		if (name.contains("-")) {
//			name = name.split("-")[0];
//		}
//
//		if (name == "/undefined") {
//			// this should be done as a typedef, but we can't get "/undefined" by path for some reason.
//			return "0x0003";
//		}

		// some BitFieldDataTypes do not have a source archive... no idea why
		SourceArchive source = dt.getSourceArchive();
		if (source != null) {
			name = String.format("%s:%s", dt.getSourceArchive().getName(), name);
		}

		// a BitField does not have a unique name, so we create one
		// The hashCode is based on basetype.hashcode, bitOffset and bitSize...
		// so basetype.name:bitSize:bitOffset should be unique.
		if (dt instanceof BitFieldDataType) {
			name = String.format("%s:%d", name, ((BitFieldDataType) dt).getBitOffset());
		}

		// some types don't have UniversalIDs, so we use the name instead
		return name;
	}

	private String GetId(DataType dt) {
		if (dt instanceof FunctionDefinition) {
			FunctionDefinition function = (FunctionDefinition) dt;
			// Function names are not unique; key procedure records by their complete signature.
			StringBuilder id = new StringBuilder(GetIdUnmapped(dt));
			id.append("@fn(").append(function.getCallingConventionName()).append("):");
			id.append(GetId(function.getReturnType())).append("(");
			for (ParameterDefinition argument : function.getArguments()) {
				id.append(GetId(argument.getDataType())).append(";");
			}
			return id.append(")").toString();
		}

		String key = GetIdUnmapped(dt);

		// follow the typedefs to the original type.
		while (typedefs.containsKey(key)) {
			assert key != typedefs.get(key);
			key = typedefs.get(key);
		}

		return key;
	}

	// Get the new ID for a type that has been forward declared.
	private String GetFwdId(DataType dt) {
		String id = GetId(dt);
		if (!forwardDeclared.containsKey(id)) {
			String alias = UUID.randomUUID().toString();
			forwardDeclared.put(id, alias);
		}
		return forwardDeclared.get(id);
	}

	private JsonObject dump(Pointer x) {
		if (!isSerialized(x.getDataType())) return null;

		JsonObject json = new JsonObject();
		json.addProperty("id", GetId(x));
		json.addProperty("type", "LF_POINTER");
		json.addProperty("referent_type", GetId(x.getDataType()));
		return json;
	}

	private JsonObject dump(Array x) {
		if (!isSerialized(x.getDataType())) return null;

		JsonObject json = new JsonObject();
		json.addProperty("id", GetId(x));
		json.addProperty("type", "LF_ARRAY");
		// TODO currently this is set to QWORD, is this different for x86/x64?
		json.addProperty("index_type", "0x0077");
		json.addProperty("element_type", GetId(x.getDataType()));
		json.addProperty("size", x.getLength());
		return json;
	}

	private JsonObject dump(Union x) {
		JsonArray members = new JsonArray();
		for (DataTypeComponent dt : x.getComponents()) {
			if (!isSerialized(dt.getDataType())) return null;
			JsonObject json = new JsonObject();
			json.addProperty("type", "LF_MEMBER");
			// TODO currently this is set to QWORD, is this different for x86/x64?
			json.addProperty("name", dt.getFieldName());
			json.addProperty("type_id", GetId(dt.getDataType()));
			json.addProperty("offset", dt.getOffset());
			json.add("attributes", new JsonArray());
			members.add(json);
		}

		JsonObject json = new JsonObject();
		json.addProperty("id", GetFwdId(x));
		json.addProperty("type", "LF_UNION");
		json.addProperty("name", x.getName());
		json.addProperty("unique_name", GetFwdId(x));
		json.addProperty("size", x.getLength());
		json.add("fields", members);
		json.add("options", new JsonArray());
		return json;
	}

	private JsonObject dump(Enum x) {
		JsonArray fields = new JsonArray();
		for (long value : x.getValues()) {
			JsonObject json = new JsonObject();
			json.addProperty("name", x.getName(value));
			json.addProperty("value", value);
			fields.add(json);
		}
		JsonObject json = new JsonObject();
		json.addProperty("id", GetFwdId(x));
		json.addProperty("type", "LF_ENUM");
		json.addProperty("size", x.getLength());
		json.addProperty("underlying_type", "0x0074");
		json.addProperty("name", x.getName());
		json.addProperty("unique_name", GetFwdId(x));
		json.add("fields", fields);
		json.add("options", new JsonArray());
		return json;
	}

	private JsonObject dump(Structure x) {
		JsonArray fields = new JsonArray();
		for (DataTypeComponent dt : x.getComponents()) {
			if (!isSerialized(dt.getDataType())) {
				return null;
			}

			JsonObject json = new JsonObject();
			json.addProperty("type", "LF_MEMBER");
			json.addProperty("type_id", GetId(dt.getDataType()));
			json.addProperty("offset", dt.getOffset());
			json.add("attributes", new JsonArray());
			if (dt.getFieldName() == null) {
				json.addProperty("name", dt.getDefaultFieldName());
			} else {
				json.addProperty("name", dt.getFieldName());				
			}

			if (dt.isBitFieldComponent()) {
				// TODO implement this
				// BitFieldDataType bfdt = (BitFieldDataType) dt.getDataType();
			}

			fields.add(json);
		}

		JsonObject json = new JsonObject();
		json.addProperty("id", GetFwdId(x));
		json.addProperty("type", "LF_STRUCTURE");
		json.addProperty("name", x.getName());
		json.addProperty("size", x.getLength());
		json.addProperty("unique_name", GetFwdId(x));
		json.add("options", new JsonArray());
		json.add("fields", fields);
		return json;
	}

	private JsonObject dump(BitFieldDataType x) {
		if (!isSerialized(x.getBaseDataType())) return null;

		JsonObject json = new JsonObject();
		json.addProperty("id", GetId(x));
		json.addProperty("type", "LF_BITFIELD");
		json.addProperty("type_id", GetId(x.getBaseDataType()));
		json.addProperty("bit_offset", x.getBitOffset());
		json.addProperty("bit_size", x.getBitSize());
		return json;
	}

	private List<JsonObject> dump(FunctionDefinition x) {
//		// There should be a good way of determining class, but I haven't found it yet
//		// So instead I'm just gonna check calling convention and lookup the type manually.
//		if (x.getGenericCallingConvention() == GenericCallingConvention.thiscall) {
//			DataType clz = x.getArguments()[0].getDataType();
//			if (clz instanceof Pointer) {
//				clz = ((Pointer) clz).getDataType();
//			}
//			printf("%s::%s()\n", clz.getName(), x.getName());
//		}
//		printf("function [%s] %s %s", x.getName(), GetId(x), x.getClass().getName());

		// we wait (return null) until we have dumped all the dependant types
		if (!isSerialized(x.getReturnType())) return null;
		JsonArray parameters = new JsonArray();
		for (ParameterDefinition p : x.getArguments()) {
			if (!isSerialized(p.getDataType())) return null;
			parameters.add(GetId(p.getDataType()));
		}
		List<JsonObject> entries = new ArrayList<JsonObject>();

		JsonObject json = new JsonObject();
		json.addProperty("type", "LF_PROCEDURE");
		json.addProperty("id", GetId(x));
		json.addProperty("name", x.getName());
		json.addProperty("return_type", GetId(x.getReturnType()));
		json.addProperty("calling_convention", x.getCallingConventionName());
		json.add("options", new JsonArray());
		json.add("parameters", parameters);
		entries.add(json);

		json = new JsonObject();
		// We are creating a new id here just so it flows through our pipeline correctly with the rest of the types.
		json.addProperty("type", "LF_FUNC_ID");
		json.addProperty("id", UUID.randomUUID().toString());
		json.addProperty("name", x.getName());
		json.addProperty("function_type", GetId(x));
		json.addProperty("parent_scope", "0x0000"); // placeholder
		entries.add(json);

		return entries;
	}

	private JsonObject dump(TypeDef dt) {
		DataType base = dt.getBaseDataType();
		if (!isSerialized(base)) {
			return null;
		}
		typedefs.put(GetIdUnmapped(dt), GetIdUnmapped(dt.getBaseDataType()));
		JsonObject json = new JsonObject();
//		json.addProperty("", null);
		return json;
	}

	private List<JsonObject> toJson(DataType dt) {
		if (dt instanceof FunctionDefinition) {
			if (isSerialized(dt)) {
				return new ArrayList<JsonObject>();
			}
			return dump((FunctionDefinition) dt);
		}

		List<JsonObject> entries = new ArrayList<JsonObject>();
		JsonObject json = null;
		if (dt instanceof Pointer) {
			json = dump((Pointer) dt);
		} else if (dt instanceof BitFieldDataType) {
			json = dump((BitFieldDataType) dt);
		} else if (dt instanceof Array) {
			json = dump((Array) dt);
		} else if (dt instanceof Union) {
			json = dump((Union) dt);
		} else if (dt instanceof Enum) {
			json = dump((Enum) dt);
		} else if (dt instanceof Structure) {
			json = dump((Structure) dt);
		} else if (dt instanceof DefaultDataType) {
			// this is "undefined" which is predefined by codeview, so we will skip it here.
			return entries;
		} else if (dt instanceof TypeDef){
			json = dump((TypeDef) dt);
			// Not required... we map typedefs to their underlying type before processing the rest of the types
			// I have not found any CodeView type for typedefs, so we map the types (AFAIK like the linker does).
			// implementing this *might* cleanup the output a little, but not sure if the juice is worth the squeeze
			if (json == null) {
				return null;
			} else {
				return entries;
			}
		} else {
			printf("[PDBGEN] Unknown Type: id=%s, name=%s, class=%s\n", GetId(dt), dt.getName(), dt.getClass().getName());
		}

		if (json == null) {
			return null;
		}

		entries.add(json);
		return entries;
	}

	public void printMissing(DataType dt) {
		if (dt instanceof BuiltIn) {
			 if(dt instanceof PointerDataType) {
				printMissing((Pointer) dt);
			} else {
				printf("[PDBGEN] missing: BuiltIn '%s' missing, size=%d\n", GetIdUnmapped(dt), dt.getLength());
			}
		} else if (dt instanceof FunctionDefinition) {
			printMissing((FunctionDefinition) dt);
		} else if (dt instanceof Pointer) {
			printMissing((Pointer) dt);
		} else if (dt instanceof Array) {
			printMissing((Array) dt);
		} else if (dt instanceof Structure) {
			printMissing((Structure) dt);
		} else if (dt instanceof Union) {
			printMissing((Union) dt);
		} else if (dt instanceof DefaultDataType) {
			printMissing((DefaultDataType) dt);
		} else if (dt instanceof TypeDef) {
			printMissing((TypeDef) dt);
		} else if (dt instanceof Enum) {
			printMissing((Enum) dt);
		} else if (dt instanceof BitFieldDataType) {
			printMissing((BitFieldDataType) dt);
		} else {
			printf("[PDBGEN] missing: Unknown data type id='%s', type=%s\n", GetIdUnmapped(dt), dt.getClass().getName());
		}
	}

	public void printMissing(FunctionDefinition dt) {
		if (!isSerialized(dt.getReturnType())) {
			printf("[PDBGEN] missing: FunctionDefinition '%s' missing return type '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(dt.getReturnType()));
		}

		for (ParameterDefinition argument : dt.getArguments()) {
			if (!isSerialized(argument.getDataType())) {
				printf("[PDBGEN] missing: FunctionDefinition '%s' missing argument type '%s' for '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(argument.getDataType()), argument.getName());
			}
		}
	}

	public void printMissing(Pointer dt) {
		if (!isSerialized(dt.getDataType())) {
			printf("[PDBGEN] missing: Pointer '%s' missing base type '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(dt.getDataType()));
		}
	}

	public void printMissing(Array dt) {
		if (!isSerialized(dt.getDataType())) {
			printf("[PDBGEN] missing: Array '%s' missing base type '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(dt.getDataType()));
		}
	}

	public void printMissing(Structure dt) {
		for (DataTypeComponent component : dt.getComponents()) {
			if (!isSerialized(component.getDataType())) {
				printf("[PDBGEN] missing: Structure '%s' missing component type '%s' for field '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(component.getDataType()), component.getFieldName());
			}
		}
	}

	public void printMissing(Union dt) {
		for (DataTypeComponent component : dt.getComponents()) {
			if (!isSerialized(component.getDataType())) {
				printf("[PDBGEN] missing: Union '%s' missing component type '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(component.getDataType()));
			}
		}
	}

	public void printMissing(Enum dt) {
		printf("[PDBGEN] missing: Enum missing '%s'\n", GetIdUnmapped(dt));
	}

	public void printMissing(DefaultDataType dt) {
		printf("[PDBGEN] missing: DefaultDataType missing '%s'\n", GetIdUnmapped(dt));
	}

	public void printMissing(TypeDef dt) {
		if (!isSerialized(dt.getBaseDataType())) {
			printf("[PDBGEN] missing: TypeDef '%s' missing base type '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(dt.getBaseDataType()));
		}
	}

	public void printMissing(BitFieldDataType dt) {
		if (!isSerialized(dt.getBaseDataType())) {
			printf("[PDBGEN] missing: BitField '%s' missing base type '%s'\n", GetIdUnmapped(dt), GetIdUnmapped(dt.getBaseDataType()));
		}
	}


	public JsonArray toJson(List<DataType> datatypes) throws CancelledException {
		monitor.setMessage("Extracting DataTypes");
		monitor.initialize(datatypes.size());
		monitor.setIndeterminate(false);
		monitor.setShowProgressValue(true);
		monitor.setCancelEnabled(true);
		// Build forward declarations for everything, basically because I'm lazy.
		// We should only need to add forward declarations for data types that have cyclic dependencies.
		JsonArray json = buildForwardDeclarations(datatypes);

		// A naive ordered serialization. We continually iterate through the list,
		// serializing data types only once they have had all their dependencies serialized.
		// we stop looping over the list once we fail to serialize at least one data type.
		// Any data types that are missing dependent types will be left in the input list.
		while (!datatypes.isEmpty()) {
			boolean changed = false;
			Iterator<DataType> itr = datatypes.iterator();
			while (itr.hasNext()) {
				monitor.checkCanceled();

				DataType dt = itr.next();
				List<JsonObject> entries = toJson(dt);
				if (entries == null) {
//					 printf("skipped: %s (%s)\n", dt.getName(), GetId(dt));
					continue; // waiting for dependencies to added first
				}

				if (filterConfiguration.verbose) {
					printf("[PDBGEN] dumped: id=%s, original=%s\n", GetId(dt), GetIdUnmapped(dt));
				}
				itr.remove();
				for (JsonObject entry : entries) {
					json.add(entry);
				}
				setSerialized(dt);
				changed = true;
				monitor.incrementProgress(1);
			}

			if (!changed) {
				break; // we failed to remove any data types.
			}
		}

		for (DataType dt : datatypes ) {
			printMissing(dt);
		}

		printf("[PDBGEN] missing: %d\n", datatypes.size());
		return json;
	}

	public JsonArray buildForwardDeclarations(List<DataType> datatypes) {
		// some data that is common to all forward declarations
		JsonArray fields = new JsonArray();
		JsonArray options = new JsonArray();
		options.add("forwardref");

		JsonArray objs = new JsonArray();
		for (DataType dt : datatypes) {
			JsonObject json = new JsonObject();

			// the forward declared type and the actual type need different IDs
			// to make things easy, we use the original id in the forward declaration
			// so we do not need to rewrite the all the references.
			// We create a new Id for the actual type, because nothing else references it.
			json.addProperty("id", GetId(dt));

			if (dt instanceof Enum) {
				json.addProperty("type", "LF_ENUM");
				json.addProperty("underlying_type", "0x0000");
			} else if (dt instanceof Union) {
				json.addProperty("type", "LF_UNION");
			} else if (dt instanceof Structure) {
				json.addProperty("type", "LF_STRUCTURE");
			} else {
				continue; // we do not need to forward declare this type
			}


			// PDB resolves forward declarations by looking for other types with the same unique name,
			// if it does not find one, it will match on name instead.
			// I'm not sure if this can cause inconsistency if unique_name is not used...
			// To avoid issues, we use a uuid for the unique name to consistently match correctly.
			json.addProperty("name", dt.getName());
			json.addProperty("unique_name", GetFwdId(dt));
			json.addProperty("size", 0);
			json.add("options", options);
			json.add("fields", fields);

			objs.add(json);
			setSerialized(dt);
		}
		return objs;
	}

	public List<DataType> getAllDataTypes() {
		List<DataType> datatypes = new ArrayList<DataType>();
		// this function, despite its name, does not return all datatypes :(
		// we are going to have to go find the missing ones.
		currentProgram.getDataTypeManager().getAllDataTypes(datatypes);

		// for some reason, Ghidra does not include BitField DataTypes in getAllDataTypes, so we manually add them here.
		Iterator<Composite> composites = currentProgram.getDataTypeManager().getAllComposites();
		while (composites.hasNext()) {
			Composite composite = composites.next();
			for (DataTypeComponent component :  composite.getComponents()) {
				datatypes.add(component.getDataType());
			}
		}

		// Function signatures are not part of the data type manager.
		for (Map.Entry<Address, FunctionDefinition> entry : entrypoints.entrySet()) {
			FunctionDefinition signature = entry.getValue();
			datatypes.add(signature);
			for (ParameterDefinition argument : signature.getArguments()) {
				datatypes.add(argument.getDataType());
			}
		}

		// remove data types that we do not need to serialize for the pdb
		Iterator<DataType> itr = datatypes.iterator();
		while (itr.hasNext()) {
			DataType dt = itr.next();
			if (dt instanceof PointerDataType) {
				// technically a BuiltInDataType, however some thiscall "this" parameters are defined like this :(
				continue;
			} else if (dt instanceof BuiltIn) {
				if (typedefs.containsKey(dt.getName())) {
					String value = typedefs.get(dt.getName());
					typedefs.put(GetIdUnmapped(dt), value);
				}
				itr.remove();
				if (isSerialized(dt)) {
					// normal built in (int, bool, char*, etc)
					continue;
				}
//				printf("[PDBGEN] removed: %s (%s)\n", dt.getName(), dt.getClass().getName());
			} else if (dt instanceof TypeDef) {
				// any other typedefs that are not explictly defined by codeview
//				DataType basetype = ((TypeDef) dt).getBaseDataType();
//				typedefs.put(GetIdUnmapped(dt), GetIdUnmapped(basetype));
//				typedefs.put(dt.getName(), GetIdUnmapped(basetype));
//				itr.remove();
			}
		}

		Map<String, DataType> uniqueTypes = new LinkedHashMap<String, DataType>();
		for (DataType dt : datatypes) {
			uniqueTypes.putIfAbsent(GetId(dt), dt);
		}
		return new ArrayList<DataType>(uniqueTypes.values());
	}


	public List<Symbol> getAllSymbols() {
		List<Symbol> symbols = new ArrayList<Symbol>();
		for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(false)) {
			if (symbol.isExternal()) continue;
			symbols.add(symbol);
		}
		return symbols;
	}

	public JsonArray toJsonSymbols(List<Symbol> symbols) throws CancelledException {
		monitor.setMessage("Extracting Symbols");
		monitor.initialize(symbols.size());
		monitor.setShowProgressValue(true);
		monitor.setIndeterminate(false);
		monitor.setCancelEnabled(true);

		JsonArray objs = new JsonArray();
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			SymbolType stype = symbol.getSymbolType();
//			SourceType source = symbol.getSource();
			Address address = symbol.getAddress();

//			// We can do some interesting filtering based on where the symbol came from.
//			if (source == SourceType.ANALYSIS) {
//			} else if (source == SourceType.DEFAULT) {
//			} else if (source == SourceType.IMPORTED) {
//			} else if (source == SourceType.USER_DEFINED) {
//			}

			String name = symbol.getName(true);
			if (stype == SymbolType.CLASS) {
			} else if (stype == SymbolType.FUNCTION) {
				Function function = exportableFunctions.get(address);
				if (function == null) {
					continue;
				}
				// we rename any thunks to easily distinguish them from the actual functions
				if (function.isThunk() && !name.startsWith("thunk_")) {
					name = "thunk_"+name;
				}

				JsonObject json = new JsonObject();
				json.addProperty("type", "S_PUB32");
				json.addProperty("name", name);
				json.addProperty("address", address.getUnsignedOffset());
				json.addProperty("function", true);
				objs.add(json);

				if (function.isThunk()) continue;

				// for what ever reason, the ID of the FunctionSignature is different from when we dumps the types,
				// so we cache the original type, and use the function's address to find it now.
				FunctionDefinition definition = entrypoints.get(address);
				if (definition == null) {
					continue;
				}

				String id = GetId(definition);
//				printf("signature [%s] %s %s", definition.getName(), id, definition.getClass().getName());


//				// I dont have a good way of looking up the FunctionDefinition id from here. will probably need a refactor.
				Address start = function.getBody().getMinAddress();
				Address end = function.getBody().getMaxAddress();


				if (!start.hasSameAddressSpace(end)) {
					// TODO: Generate symbols in a sane way when there are multiple "address ranges" for a function.
					// The above functions will return the start of the lowest range, and the end of the highest range
					// which is absolutely not what we want, so we are gonna skip them for now.
					continue;
				}

				// S_GPROC32
				json = new JsonObject();
				json.addProperty("type", "S_GPROC32");
				json.addProperty("name", name);
				json.addProperty("address", start.getUnsignedOffset());
				json.addProperty("code_size", end.subtract(start)+1);
				json.addProperty("end", 0);
				json.addProperty("function_type", id);
				json.addProperty("debug_start", 0);
				json.addProperty("debug_end", 0);
				json.addProperty("parent", "0x0000");
				json.add("flags", new JsonArray());
				objs.add(json);

				json = new JsonObject();
				json.addProperty("type", "S_END");
				objs.add(json);

//				// S_PROCREF
//				fmt = "{\"type\": \"S_PROCREF\", \"name\": \"%s\", \"address\": %d, \"code_size\": \"%d\", \"function_type\": \"%s\", \"debug_start\": %d, \"debug_end\": %d, \"parent\": \"%s\", \"flags\": []}";
//				lines.add(String.format(fmt,  name, start.getUnsignedOffset(), end.subtract(start)+1, id, 0, 0, "0x0000"));
			} else if (stype == SymbolType.GLOBAL || stype == SymbolType.GLOBAL_VAR) {
				JsonObject json = new JsonObject();
				json.addProperty("type", "S_PUB32");
				json.addProperty("name", name);
				json.addProperty("address", address.getUnsignedOffset());
				json.addProperty("function", false);
				objs.add(json);

			} else if (stype == SymbolType.LABEL) {
			} else if (stype == SymbolType.CLASS) {
			} else if (stype == SymbolType.LIBRARY) {
			} else if (stype == SymbolType.LOCAL_VAR) {
			} else if (stype == SymbolType.NAMESPACE) {
			} else if (stype == SymbolType.PARAMETER) {
			} else {
				// unknown symbol type
			}
		}
		return objs;
	}

	public void initializeTypeDefs() {
		// map Ghidra built-in types that are predefined by CodeView
		// these do not have a UniversalID so we reference them by their name instead.
		// note: name may not be unique, but its all i have found so far.

		Map<String, String> aliases = new HashMap<String, String>();
		aliases.put("/undefined", "0x0003"); // we have to do this manually in GetIdUnmapped
		aliases.put("BuiltInTypes:/null", "0x0000");
		aliases.put("BuiltInTypes:/void", "0x0003");
		aliases.put("BuiltInTypes:/bool", "0x0030");
		aliases.put("BuiltInTypes:/byte", "0x0069");
		aliases.put("BuiltInTypes:/sbyte", "0x0068");
		aliases.put("BuiltInTypes:/char", "0x0070");
		aliases.put("BuiltInTypes:/wchar_t", "0x0071");
		aliases.put("BuiltInTypes:/char16_t", "0x007A");
		aliases.put("BuiltInTypes:/char32_t", "0x007B");
		aliases.put("BuiltInTypes:/uchar", "0x0020");
		aliases.put("BuiltInTypes:/wchar16", "0x007A");
		aliases.put("BuiltInTypes:/wchar32", "0x007B");
		aliases.put("BuiltInTypes:/short", "0x0011");
		aliases.put("BuiltInTypes:/ushort", "0x0021");
		aliases.put("BuiltInTypes:/int", "0x0074");
		aliases.put("BuiltInTypes:/uint", "0x0075");
		aliases.put("BuiltInTypes:/long", "0x0012");
		aliases.put("BuiltInTypes:/ulong", "0x0022");
		aliases.put("BuiltInTypes:/longlong", "0x0076");
		aliases.put("BuiltInTypes:/ulonglong", "0x0077");
		aliases.put("BuiltInTypes:/uint128_t", "0x0079");
		aliases.put("BuiltInTypes:/word", "0x0073");
		aliases.put("BuiltInTypes:/dword", "0x0075");
		aliases.put("BuiltInTypes:/qword", "0x0077");
		aliases.put("BuiltInTypes:/float", "0x0040");
		aliases.put("BuiltInTypes:/double", "0x0041");
		aliases.put("BuiltInTypes:/float10", "0x0042");

		aliases.put("BuiltInTypes:/string", "0x0670");
		aliases.put("BuiltInTypes:/string-utf8", "0x0670");
		aliases.put("BuiltInTypes:/unicode", "0x067A");
		aliases.put("BuiltInTypes:/unicode32", "0x067B");
		aliases.put("BuiltInTypes:/TerminatedCString", "0x0670");
		aliases.put("BuiltInTypes:/ImageBaseOffset32", "0x0075");
		aliases.put("BuiltInTypes:/ImageBaseOffset64", "0x0076");

		aliases.put("BuiltInTypes:/uint3", "0x0075");
		aliases.put("BuiltInTypes:/longdouble", "0x0042");

		aliases.put("BuiltInTypes:/undefined1", "0x0069");
		aliases.put("BuiltInTypes:/undefined2", "0x0021");
		aliases.put("BuiltInTypes:/undefined3", "0x0022");
		aliases.put("BuiltInTypes:/undefined4", "0x0022");
		aliases.put("BuiltInTypes:/undefined5", "0x0077");
		aliases.put("BuiltInTypes:/undefined6", "0x0077");
		aliases.put("BuiltInTypes:/undefined7", "0x0077");
		aliases.put("BuiltInTypes:/undefined8", "0x0077");


		aliases.put("BuiltInTypes:/GUID", "0x0079");
		aliases.put("BuiltInTypes:/IMAGE_RICH_HEADER", "0x0069");
		aliases.put("BuiltInTypes:/PEx64_UnwindInfo", "0x069");

		for (String key : aliases.keySet()) {
			String value = aliases.get(key);
			if (filterConfiguration.verbose) {
				printf("alias: %s -> %s\n", key, value);
			}
			DataType dt = currentProgram.getDataTypeManager().getDataType(key);
			String typeid = GetIdUnmapped(dt);

			typedefs.put(key, value);
			typedefs.put(typeid, value);

			serialized.add(key);
			serialized.add(typeid);
		}

		for (String value : aliases.values()) {
			if (value.startsWith("0x")) {
				serialized.add(value);
			}
		}
	}

	public static List<String> readAll(InputStream in) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		List<String> lines = new ArrayList<String>();
		while (reader.ready()) {
			lines.add(reader.readLine());
		}
		return lines;
	}

	public String getDbgPath(String base) throws Exception {
		String exePath = FilenameUtils.normalize(currentProgram.getExecutablePath());
		String dbgName = FilenameUtils.getBaseName(exePath).concat(".dbg");

		// Get PortableExecutable from the current program
		Memory memory = currentProgram.getMemory();
		ByteProvider provider = new MemoryByteProvider(memory, currentProgram.getImageBase());
		PortableExecutable pe = new PortableExecutable(provider, PortableExecutable.SectionLayout.MEMORY);
		
		// Get NT Header (IMAGE_NT_HEADERS)
		NTHeader ntHeader = pe.getNTHeader();
		if (ntHeader == null) {
			println("NT header not found.");
		}

		// Get the Optional Header (IMAGE_OPTIONAL_HEADER)
		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
		if (optionalHeader == null) {
			println("Optional header not found.");
		}

		FileHeader fileHeader = ntHeader.getFileHeader();
		
		String timeDateStamp = Integer.toHexString(fileHeader.getTimeDateStamp());
		String imageSize = Long.toHexString(optionalHeader.getSizeOfImage());

		return Paths.get(base, dbgName, timeDateStamp+imageSize, dbgName).toString();
	}
	
	public String getPdbPath(String base) {
		SymbolFileInfo info = SymbolFileInfo.fromProgramInfo(currentProgram);
		if (info == null) {
			return null;
		}

		String filename = info.getName();
		return Paths.get(base, filename, info.getUniqueDirName(), filename).toString();
	}

	public String getSymbolOutputPath() throws Exception {
		if (OVERRIDE_SYMBOL_OUTPUT_PATH != null) {
			return OVERRIDE_SYMBOL_OUTPUT_PATH;
		}

		// TODO use the LocalSymbolStore in an intelligent manner
//		SymbolServerInstanceCreatorContext context = SymbolServerInstanceCreatorRegistry.getInstance().getContext(currentProgram);
//		SymbolServerService service = PdbPlugin.getSymbolServerService(context);
//		SymbolStore store = service.getSymbolStore();

		// Get the Symbol Output Path were we will save all our future pdbs.
		String symbolOutputPath = Preferences.getProperty(PREFERENCE_SYMBOL_OUTPUT_PATH);
		if (symbolOutputPath == null) {
			symbolOutputPath = askDirectory("Select Symbol Output Path", "Set Symbol Output Path").getAbsolutePath();
			Preferences.setProperty(PREFERENCE_SYMBOL_OUTPUT_PATH, symbolOutputPath);
		} else {
			printf("Using saved symbol output directory '%s'\n", symbolOutputPath);
			printf("modify '%s' in '%s' to change symbol output location\n", PREFERENCE_SYMBOL_OUTPUT_PATH, Preferences.getFilename());
		}

		return symbolOutputPath;
	}
	
	private void runExport() throws Exception {
		configureFiltering();
		if (state.getTool() != null) {
			ConsoleService console = state.getTool().getService(ConsoleService.class);
			console.clearMessages();
		}

		String symbolOutputPath = getSymbolOutputPath();
		File baseSymbolDir = new File(symbolOutputPath);
		if (!baseSymbolDir.exists()) {
			String msg = String.format("The symbol output directory \"%s\" does not exit", baseSymbolDir.getAbsolutePath());
			if (askYesNo("create symbol output directory", msg+", would you like to create it?")) {
				baseSymbolDir.mkdirs();
			} else {
				printerr(msg);
				return;
			}
		}
		printf("base symbol path: %s\n", symbolOutputPath);

		String output = getPdbPath(symbolOutputPath);
		if (output == null) {
			// TODO generate .dbg file instead, or ask for a location to save to
			popup("Unable to create a PDB!\n\nThe original binary is missing the required PDB signature/guid and age information.");
			return;
		}

		// clear types from the last run
		typedefs.clear();
		serialized.clear();
		forwardDeclared.clear();
		entrypoints.clear();
		exportableFunctions.clear();
		filterStatistics.discovered = 0;
		filterStatistics.exported = 0;
		filterStatistics.unwindSkipped = 0;
		filterStatistics.runtimeSkipped = 0;
		filterStatistics.importThunksSkipped = 0;
		filterStatistics.compilerSkipped = 0;
		filterStatistics.nonExecutableSkipped = 0;
		filterStatistics.externalSkipped = 0;
		filterStatistics.typeRecords = 0;
		filterStatistics.symbolRecords = 0;
		filterStatistics.examples.clear();
		filterStatistics.startNanos = System.nanoTime();

		// setup typedefs so we can map to basic types
		initializeTypeDefs();
		discoverFunctions();

		JsonObject json = new JsonObject();

		// Now serialize all the data types (in dependency order)
		JsonArray typeRecords = toJson(getAllDataTypes());
		JsonArray symbolRecords = toJsonSymbols(getAllSymbols());
		filterStatistics.typeRecords = typeRecords.size();
		filterStatistics.symbolRecords = symbolRecords.size();
		json.add("types", typeRecords);
		json.add("symbols", symbolRecords);


		// Ghidra has unhelpfully set the path to \C:\\Something\ this gives as a normal c:\\Something
		String exepath = Path.fromPathString(currentProgram.getExecutablePath()).toString();
		printf("executable: %s\n", exepath);
		String jsonpath = FilenameUtils.removeExtension(output).concat(".json");

		File pdbfile = new File(output);
		if (pdbfile.exists()) {
			if (!askYesNo("overwrite pdb", "are you sure you want to overwrite \""+pdbfile.getAbsolutePath()+"\"")) {
				return;
			}
			pdbfile.delete();
		} else {
			pdbfile.getParentFile().mkdirs();
		}

		String jsonText = json.toString();
		try (FileWriter w = new FileWriter(jsonpath)) {
			w.write(jsonText);
		}

		monitor.setIndeterminate(true);
		monitor.setCancelEnabled(true);

		ProcessBuilder pdbgen = new ProcessBuilder();
		printf("[PDBGEN] Launching generator: %s\n", pdbgenExecutable);
		pdbgen.command(pdbgenExecutable, exepath, "-", "--output", output);

		Process proc;
		try {
			proc = pdbgen.start();
		} catch (IOException e) {
			throw new IOException("Unable to start PdbGen executable '" +
				pdbgenExecutable + "'. Set PDBGEN_EXE or pass --pdbgen-exe <path>.",
				e);
		}
		PrintWriter stdin = new PrintWriter(proc.getOutputStream());
		stdin.write(jsonText);
		stdin.close();

		while (proc.isAlive()) {
			if (monitor.isCancelled()) {
				monitor.setMessage("Stopping pdbgen.exe");
				proc.destroy();
			}

			for (String line : readAll(proc.getInputStream())) {
				println(line);
			}
	
			for (String line : readAll(proc.getErrorStream())) {
				printerr(line);
			}

			proc.waitFor(100, TimeUnit.MILLISECONDS);
		}

		printFilterStatistics(jsonpath);
		return;
	}

	public void run() throws Exception {
		try {
			runExport();
		} catch (Exception e) {
			printerr("[PDBGEN] ERROR: " + e.getClass().getName());
			printerr("[PDBGEN] MESSAGE: " +
				(e.getMessage() == null ? "(no message)" : e.getMessage()));
			StringWriter trace = new StringWriter();
			e.printStackTrace(new PrintWriter(trace));
			printerr(trace.toString());
			throw e;
		}
	}
}