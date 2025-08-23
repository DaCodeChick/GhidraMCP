package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public class GetCallee extends Handler {
    public GetCallee(PluginTool tool) {
        super(tool, "/get_callee");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Map<String, String> qparams = parseQueryParams(exchange);
        String addressStr = qparams.get("address");
        sendResponse(exchange, getCallee(addressStr));
    }

    private String getCallee(String addressStr) {
        if (addressStr == null) {
            return "Missing address parameter";
        }

        try {
            Program currentProgram = getCurrentProgram(tool);
            if (currentProgram == null) {
                return "No active program";
            }

            Address address = currentProgram.getAddressFactory().getAddress(addressStr);
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(address);

            if (fn == null) {
                return "No function at the specified address";
            }

            Set<Function> callees = fn.getCalledFunctions(TaskMonitor.DUMMY);
            if (callees.isEmpty()) {
                return "(no callees)";
            }

            List<String> calleeList = new ArrayList<>();
            for (Function callee : callees) {
                calleeList.add(String.format("%s @ %s", callee.getName(true), callee.getEntryPoint()));
            }
            Collections.sort(calleeList, String.CASE_INSENSITIVE_ORDER);

            return String.join("\n", calleeList);
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }
}