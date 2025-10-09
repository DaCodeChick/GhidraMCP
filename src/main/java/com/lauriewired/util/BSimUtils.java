package com.lauriewired.util;

import ghidra.app.services.ProgramManager;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.File;

import static GhidraUtils.*;

/**
 * Utility class for BSim database operations.
 */
public final class BSimUtils {
	/** The BSim database instance */
	public static FunctionDatabase bsimDatabase = null;

	/** The current BSim database path */
    public static String currentBSimDatabasePath = null;

	/**
	 * Disconnects from the BSim database.
	 *
	 * @return A message indicating the result of the disconnection attempt.
	 */
	public static String disconnectBSimDatabase() {
        if (bsimDatabase != null) {
            try {
                bsimDatabase.close();
                bsimDatabase = null;
                String path = currentBSimDatabasePath;
                currentBSimDatabasePath = null;
                return "Disconnected from BSim database: " + path;
            } catch (Exception e) {
                return "Error disconnecting from BSim database: " + e.getMessage();
            }
        }
        return "No BSim database connection to disconnect";
    }

	/**
	 * Recursively searches for a DomainFile by name within a DomainFolder and its subfolders.
	 *
	 * @param folder   The starting DomainFolder to search within.
	 * @param fileName The name of the DomainFile to find.
	 * @return The found DomainFile, or null if not found.
	 */
	public static DomainFile findDomainFileRecursive(
            DomainFolder folder, String fileName) {

        // Check files in current folder
        for (DomainFile file : folder.getFiles()) {
            if (fileName.equals(file.getName())) {
                return file;
            }
        }

        // Recursively check subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            DomainFile result = findDomainFileRecursive(subfolder, fileName);
            if (result != null) {
                return result;
            }
        }

        return null;
    }

	/**
	 * Retrieves detailed information about a matched function from the BSim database.
	 *
	 * @param executablePath The path to the executable file.
	 * @param functionName   The name of the function to match.
	 * @param functionAddress The address of the function to match.
	 * @param includeDisassembly Whether to include disassembly information.
	 * @param includeDecompile   Whether to include decompiled code.
	 * @return A string containing the match details or an error message.
	 */
	public static String getBSimMatchFunction(String executablePath, String functionName, String functionAddress,
                                        boolean includeDisassembly, boolean includeDecompile) {
        // Input validation
        if (executablePath == null || executablePath.isEmpty()) {
            return "Error: Executable path is required";
        }
        if (functionName == null || functionName.isEmpty()) {
            return "Error: Function name is required";
        }
        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }

        StringBuilder result = new StringBuilder();
        result.append("Match Details\n");
        result.append("=============\n");
        result.append(String.format("Executable: %s\n", executablePath));
        result.append(String.format("Function: %s\n", functionName));
        result.append(String.format("Address: %s\n\n", functionAddress));

        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            result.append("ERROR: ProgramManager service not available\n");
            return result.toString();
        }

        String fileName = new File(executablePath).getName();
        Program matchedProgram = null;
        boolean needsRelease = false;

        // Strategy 1: Check all open programs
        Program[] openPrograms = pm.getAllOpenPrograms();
        for (Program program : openPrograms) {
            if (executablePath.equals(program.getExecutablePath()) || fileName.equals(program.getName())) {
                matchedProgram = program;
                needsRelease = false;
                break;
            }
        }

        // Strategy 2: Try to find in project but not currently open
        if (matchedProgram == null) {
            Project project = tool.getProject();
            if (project != null) {
                DomainFile domainFile = findDomainFileRecursive(
                    project.getProjectData().getRootFolder(), fileName);

                if (domainFile != null) {
                    try {
                        DomainObject domainObject = 
                            domainFile.getDomainObject(BSimUtils.class, false, false, new ConsoleTaskMonitor());
                        if (domainObject instanceof Program) {
                            matchedProgram = (Program) domainObject;
                            needsRelease = true;
                        }
                    } catch (Exception e) {
                        Msg.error(BSimUtils.class, "Failed to open program from project: " + fileName, e);
                    }
                }
            }
        }

        if (matchedProgram == null) {
            result.append("ERROR: Program not found in Ghidra project\n");
            result.append("The matched executable is not in the current project.\n");
            result.append("\nTo view match details, please import the program into Ghidra:\n");
            result.append("  ").append(executablePath).append("\n");
            return result.toString();
        }

        try {
            // Find the function
            Address addr = matchedProgram.getAddressFactory().getAddress(functionAddress);
            Function func = matchedProgram.getFunctionManager().getFunctionAt(addr);

            if (func == null) {
                func = matchedProgram.getFunctionManager().getFunctionContaining(addr);
            }

            if (func == null) {
                result.append("ERROR: Function not found at address ").append(functionAddress).append("\n");
                return result.toString();
            }

            // Get function prototype
            result.append("Function Prototype:\n");
            result.append("-------------------\n");
            result.append(func.getSignature()).append("\n\n");

            // Get decompilation if requested
            if (includeDecompile) {
                result.append("Decompilation:\n");
                result.append("--------------\n");
                String decompCode = decompileFunctionInProgram(func, matchedProgram);
                if (decompCode != null && !decompCode.isEmpty()) {
                    result.append(decompCode).append("\n");
                } else {
                    result.append("(Decompilation not available)\n");
                }
            }

            // Get assembly if requested
            if (includeDisassembly) {
                if (includeDecompile) {
                    result.append("\n");
                }
                result.append("Assembly:\n");
                result.append("---------\n");
                String asmCode = disassembleFunctionInProgram(func, matchedProgram);
                if (asmCode != null && !asmCode.isEmpty()) {
                    result.append(asmCode);
                } else {
                    result.append("(Assembly not available)\n");
                }
            }

            return result.toString();

        } catch (Exception e) {
            result.append("ERROR: Exception while processing program: ").append(e.getMessage()).append("\n");
            Msg.error(BSimUtils.class, "Error getting BSim match function", e);
            return result.toString();
        } finally {
            // Release the program if we opened it from the project
            if (needsRelease && matchedProgram != null) {
                matchedProgram.release(BSimUtils.class);
            }
        }
    }
}
