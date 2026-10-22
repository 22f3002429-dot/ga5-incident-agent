def _attr(key, value):
    if isinstance(value, bool):
        v = {"boolValue": value}
    elif isinstance(value, int):
        v = {"intValue": value}
    else:
        v = {"stringValue": str(value)}
    return {"key": key, "value": v}


def _span(trace_id, span_id, parent_id, name, kind, start, end, attrs, error=False, links=None):
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(max(end, start)),
        "attributes": attrs,
    }
    if parent_id:
        span["parentSpanId"] = parent_id
    if error:
        span["status"] = {"code": 2}
    if links:
        span["links"] = [{"traceId": trace_id, "spanId": s} for s in links]
    return span


def build_otlp(st):
    tid = st["traceId"]
    sp = st["spanIds"]
    base = [_attr("ga5.run.id", st["runId"]), _attr("ga5.public.marker", st["publicMarker"])]
    end_all = max(st["updatedNs"], st["createdNs"])

    spans = [
        _span(tid, sp["server"], st["incomingParent"], "POST /v2/incidents", 2,
              st["createdNs"], end_all, base),
        _span(tid, sp["agent"], sp["server"], "invoke_agent incident-response", 1,
              st["createdNs"], end_all,
              base + [_attr("gen_ai.operation.name", "invoke_agent"),
                      _attr("gen_ai.agent.name", st["agentName"])]),
        _span(tid, sp["chat"], sp["agent"], "chat incident-plan", 3,
              st["createdNs"], st["createdNs"],
              base + [_attr("gen_ai.operation.name", "chat"),
                      _attr("gen_ai.request.model", st["model"])]),
    ]

    diag_exec = []
    for action_id in st["order"]:
        a = st["actions"][action_id]
        atts = a["attempts"]
        ex_start = atts[0]["startNs"]
        ex_end = max(x["endNs"] or x["startNs"] for x in atts)
        spans.append(_span(
            tid, a["executeSpanId"], sp["agent"], f"execute_tool {a['toolName']}", 1,
            ex_start, ex_end,
            base + [_attr("ga5.action.id", a["actionId"]),
                    _attr("gen_ai.tool.name", a["toolName"]),
                    _attr("gen_ai.tool.call.id", a["callId"]),
                    _attr("gen_ai.operation.name", "execute_tool")],
            error=a["state"] == "failed",
        ))
        if a["phase"] == "diagnostic":
            diag_exec.append(a["executeSpanId"])

        for att in atts:
            attrs = base + [
                _attr("ga5.action.id", a["actionId"]),
                _attr("ga5.attempt", att["attempt"]),
                _attr("http.request.method", "POST"),
                _attr("http.request.resend_count", att["attempt"] - 1),
            ]
            if att["receiptId"]:
                attrs += [_attr("ga5.receipt.id", att["receiptId"]),
                          _attr("ga5.receipt.nonce", att["nonce"])]
            if att["httpStatus"] is not None:
                attrs.append(_attr("http.response.status_code", att["httpStatus"]))
            if att["errorType"]:
                attrs.append(_attr("error.type", att["errorType"]))
            spans.append(_span(
                tid, att["clientSpanId"], a["executeSpanId"], f"POST tool/{a['toolName']}", 3,
                att["startNs"], att["endNs"] or att["startNs"], attrs,
                error=bool(att["errorType"]),
            ))

    if len(diag_exec) > 1:
        spans.append(_span(tid, sp["join"], sp["agent"], "incident.join", 1,
                           st["createdNs"], end_all, base, links=diag_exec))

    for ap in st["approvals"].values():
        if ap["status"] == "approved":
            spans.append(_span(
                tid, st["approvalGateSpanId"], sp["agent"], "approval_gate", 1,
                st["createdNs"], end_all,
                base + [_attr("ga5.approval.id", ap["approvalId"]),
                        _attr("ga5.receipt.nonce", ap["nonce"])],
            ))

    return {"resourceSpans": [{
        "resource": {"attributes": [_attr("service.name", "ga5-incident-agent")]},
        "scopeSpans": [{"scope": {"name": "ga5-incident-agent"}, "spans": spans}],
    }]}
