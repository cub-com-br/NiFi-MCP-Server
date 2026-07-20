from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import anyio

from .config import ServerConfig
from .auth import KnoxAuthFactory
from .client import NiFiClient, NiFiError
from .flow_builder import analyze_flow_request
from .best_practices import NiFiBestPractices, SmartFlowBuilder
from .setup_helper import SetupGuide


# Lazy import of MCP to give a clear error if the dependency is missing
try:
	from mcp.server import FastMCP
	from mcp.server.stdio import stdio_server
except Exception as e:  # pragma: no cover
	raise RuntimeError(
		"The 'mcp' package is required. Install with: pip install mcp"
	) from e


def _summarize_local_modifications(raw: Dict[str, Any]) -> Dict[str, Any]:
	"""Summarize a NiFi FlowComparisonEntity into a compact, LLM-friendly digest.

	Produces total counts, a histogram of differenceType values, and a
	per-componentType rollup with each affected component's id/name/change_count.
	Verbose `difference` strings are dropped; use raw=False to get full detail.
	"""
	component_diffs = raw.get("componentDifferences", []) or []
	type_histogram: Dict[str, int] = {}
	per_type: Dict[str, Dict[str, Any]] = {}
	total_diffs = 0

	for comp in component_diffs:
		comp_type = comp.get("componentType", "UNKNOWN")
		diffs = comp.get("differences", []) or []
		change_count = len(diffs)
		total_diffs += change_count
		for d in diffs:
			dt = d.get("differenceType", "UNKNOWN")
			type_histogram[dt] = type_histogram.get(dt, 0) + 1
		bucket = per_type.setdefault(comp_type, {"count": 0, "components": []})
		bucket["count"] += 1
		bucket["components"].append({
			"id": comp.get("componentId"),
			"name": comp.get("componentName"),
			"processGroupId": comp.get("processGroupId"),
			"change_count": change_count,
		})

	return {
		"componentCount": len(component_diffs),
		"totalDifferences": total_diffs,
		"differenceTypeHistogram": type_histogram,
		"byComponentType": per_type,
	}


def _redact_sensitive(obj: Any, max_items: int = 200) -> Any:
	"""Redact common sensitive fields and truncate large collections for LLMs."""
	redact_keys = {"password", "passcode", "token", "secret", "kerberosKeytab", "sslKeystorePasswd"}
	if isinstance(obj, dict):
		redacted: Dict[str, Any] = {}
		for k, v in obj.items():
			if k.lower() in redact_keys:
				redacted[k] = "***REDACTED***"
			else:
				redacted[k] = _redact_sensitive(v, max_items)
		return redacted
	if isinstance(obj, list):
		if len(obj) > max_items:
			return [_redact_sensitive(x, max_items) for x in obj[:max_items]] + [
				{"truncated": True, "omitted_count": len(obj) - max_items}
			]
		return [_redact_sensitive(x, max_items) for x in obj]
	return obj


def _project_event_attributes(data: Dict[str, Any], include_attributes: Optional[List[str]]) -> Dict[str, Any]:
	"""Project each provenance event's `attributes` list down to only the named
	attributes. No-op when include_attributes is None. Mutates and returns `data`."""
	if include_attributes is None:
		return data
	keep = set(include_attributes)
	for event in data.get("provenanceEvents", []):
		attrs = event.get("attributes")
		if isinstance(attrs, list):
			event["attributes"] = [a for a in attrs if a.get("name") in keep]
	return data


def build_client(config: ServerConfig) -> NiFiClient:
	verify = config.build_verify()
	nifi_base = config.build_nifi_base()
	cookie_domain = config.build_cookie_domain() if config.is_browser_auth() else None
	auth = KnoxAuthFactory(
		gateway_url=config.knox_gateway_url,
		token=config.knox_token,
		cookie=config.knox_cookie,
		user=config.knox_user,
		password=config.knox_password,
		token_endpoint=config.knox_token_endpoint,
		passcode_token=config.knox_passcode_token,
		verify=verify,
		auth_source=config.knox_auth_source,
		browser=config.knox_browser,
		cookie_domain=cookie_domain,
	)
	session = auth.build_session()
	return NiFiClient(
		nifi_base,
		session,
		timeout_seconds=config.timeout_seconds,
		proxy_context_path=config.proxy_context_path,
	)


def create_server(nifi: NiFiClient, readonly: bool) -> FastMCP:
	app = FastMCP("nifi-mcp-server")

	@app.tool()
	async def get_nifi_version() -> Dict[str, Any]:
		"""Get NiFi version and build information. Works with both NiFi 1.x and 2.x."""
		data = nifi.get_version_info()
		version_tuple = nifi.get_version_tuple()
		is_2x = nifi.is_nifi_2x()
		return {
			"version_info": _redact_sensitive(data),
			"parsed_version": f"{version_tuple[0]}.{version_tuple[1]}.{version_tuple[2]}",
			"is_nifi_2x": is_2x,
			"major_version": version_tuple[0],
		}

	@app.tool()
	async def get_root_process_group() -> Dict[str, Any]:
		"""Return the root process group (read-only). Works with both NiFi 1.x and 2.x."""
		data = nifi.get_root_process_group()
		return _redact_sensitive(data)

	@app.tool()
	async def list_processors(process_group_id: str) -> Dict[str, Any]:
		"""List processors in a process group (read-only). Works with both NiFi 1.x and 2.x."""
		data = nifi.list_processors(process_group_id)
		return _redact_sensitive(data)

	@app.tool()
	async def list_connections(process_group_id: str) -> Dict[str, Any]:
		"""List connections in a process group (read-only). Works with both NiFi 1.x and 2.x."""
		data = nifi.list_connections(process_group_id)
		return _redact_sensitive(data)

	@app.tool()
	async def get_bulletins(after_ms: Optional[int] = None) -> Dict[str, Any]:
		"""Get recent bulletins since a timestamp in ms (read-only). Works with both NiFi 1.x and 2.x."""
		data = nifi.get_bulletins(after_ms)
		return _redact_sensitive(data)

	@app.tool()
	async def list_parameter_contexts() -> Dict[str, Any]:
		"""List parameter contexts (read-only). Works with both NiFi 1.x and 2.x. Note: schema may differ slightly between versions."""
		data = nifi.list_parameter_contexts()
		return _redact_sensitive(data)

	@app.tool()
	async def get_controller_services(process_group_id: Optional[str] = None) -> Dict[str, Any]:
		"""Get controller services (read-only). If process_group_id is None, returns controller-level services. Works with both NiFi 1.x and 2.x."""
		data = nifi.get_controller_services(process_group_id)
		return _redact_sensitive(data)

	# ===== Additional Read-Only Tools =====

	@app.tool()
	async def get_processor_types() -> Dict[str, Any]:
		"""Get all available processor types (read-only). Useful for discovering what processors can be created."""
		data = nifi.get_processor_types()
		return _redact_sensitive(data)

	@app.tool()
	async def search_flow(query: str) -> Dict[str, Any]:
		"""Search the NiFi flow for components (read-only). Returns processors, connections, and other components matching the search query."""
		data = nifi.search_flow(query)
		return _redact_sensitive(data)

	@app.tool()
	async def get_connection_details(connection_id: str) -> Dict[str, Any]:
		"""Get details about a specific connection including queue size and relationships (read-only)."""
		data = nifi.get_connection(connection_id)
		return _redact_sensitive(data)

	@app.tool()
	async def get_processor_details(processor_id: str) -> Dict[str, Any]:
		"""Get detailed information about a specific processor including configuration (read-only)."""
		data = nifi.get_processor(processor_id)
		return _redact_sensitive(data)

	@app.tool()
	async def list_input_ports(process_group_id: str) -> Dict[str, Any]:
		"""List input ports for a process group (read-only)."""
		data = nifi.get_input_ports(process_group_id)
		return _redact_sensitive(data)

	@app.tool()
	async def list_output_ports(process_group_id: str) -> Dict[str, Any]:
		"""List output ports for a process group (read-only)."""
		data = nifi.get_output_ports(process_group_id)
		return _redact_sensitive(data)
	
	@app.tool()
	async def get_processor_state(processor_id: str) -> str:
		"""Get just the state of a processor (RUNNING, STOPPED, DISABLED, etc.).

		Quick status check without fetching full processor details.
		"""
		return nifi.get_processor_state(processor_id)

	@app.tool()
	async def get_processor_provenance(
		processor_id: str,
		max_results: int = 5,
		search_terms: Optional[Dict[str, str]] = None,
		include_attributes: Optional[List[str]] = None,
	) -> Dict[str, Any]:
		"""Get latest flowfile provenance events for a processor (read-only).

		Returns events newest-first by eventTime. Each event includes eventType
		(RECEIVE/SEND/DROP/...), eventTime, flowFileUuid, componentId,
		componentName, attributes, and lineage info. Submits a provenance query,
		polls until NiFi finishes it, returns results, and deletes the query.

		search_terms: extra key/value filters ANDed with the processor scope. Keys
		must be NiFi built-in fields or provenance-indexed flowfile attributes (call
		get_provenance_search_options to see valid keys); a non-indexed key matches
		nothing. Example: {"apiClientId": "prolotes"}.

		include_attributes: when set, each event's `attributes` is projected down to
		only these names — use it to strip large attributes and keep the response
		within token limits. Default None keeps all attributes.
		"""
		data = nifi.query_provenance_by_processor(
			processor_id, max_results=max_results, search_terms=search_terms
		)
		data = _project_event_attributes(data, include_attributes)
		return _redact_sensitive(data)

	@app.tool()
	async def get_flowfile_provenance(flowfile_uuid: str, max_results: int = 10) -> Dict[str, Any]:
		"""Get provenance events for a single FlowFile UUID across all processors (read-only).

		Returns events newest-first by eventTime — useful for finding the last
		(terminal) event of a flowfile (DROP/SEND/...) or its full event history.
		Submits a provenance query scoped by FlowFileUUID, polls until NiFi
		finishes it, returns results, and deletes the query.
		"""
		data = nifi.query_provenance_by_flowfile(flowfile_uuid, max_results=max_results)
		return _redact_sensitive(data)

	@app.tool()
	async def get_flowfile_lineage(flowfile_uuid: str) -> Dict[str, Any]:
		"""Get the lineage graph for a FlowFile UUID (read-only).

		Returns `nodes` (events and flowfile nodes) and `links`
		(parent->child edges) tracing the flowfile and its ancestors/descendants.
		Pair with get_flowfile_provenance for per-event attribute detail. Payload
		can be large for long-lived flowfiles. Submits a lineage query, polls
		until NiFi finishes it, returns results, and deletes the query.
		"""
		data = nifi.query_lineage_by_flowfile(flowfile_uuid)
		return _redact_sensitive(data)

	@app.tool()
	async def get_provenance_event_content(event_id: str, direction: str = "input") -> Dict[str, Any]:
		"""Download the content of a provenance event's flowfile (read-only).

		direction: 'input' (content claim entering the event) or 'output'.
		For DROP/terminal events use 'input'. Returns {eventId, direction,
		contentType, encoding ('utf-8'|'base64'), sizeBytes, content}.
		"""
		data = nifi.get_provenance_event_content(event_id, direction)
		return _redact_sensitive(data)

	@app.tool()
	async def get_provenance_search_options() -> Dict[str, Any]:
		"""List the provenance search fields/attributes NiFi accepts as searchTerms (read-only).

		Returns NiFi's searchable fields — built-ins plus flowfile attributes indexed
		via nifi.provenance.repository.indexed.attributes. Use this to confirm a key
		(e.g. apiClientId) is indexed before passing it as a get_processor_provenance
		search_terms filter; keys not listed here match nothing.
		"""
		data = nifi.query_provenance_search_options()
		return _redact_sensitive(data)

	@app.tool()
	async def check_connection_queue(connection_id: str) -> Dict[str, int]:
		"""Check queue size for a connection (flowfile count and bytes).
		
		Useful before deleting connections - they must be empty to delete.
		Returns: {'flowFilesQueued': int, 'bytesQueued': int}
		"""
		return nifi.get_connection_queue_size(connection_id)
	
	@app.tool()
	async def get_flow_summary(process_group_id: str) -> Dict[str, Any]:
		"""Get summary statistics for a process group.

		Returns processor counts by state, connection count, and total queued data.
		Perfect for understanding the overall health and state of a flow.
		"""
		return nifi.get_process_group_summary(process_group_id)

	@app.tool()
	async def get_version_control_info(process_group_id: str) -> Dict[str, Any]:
		"""Get version-control info for a process group (read-only, NiFi 1.x).

		Returns `{versioned: True, versionControlInformation: {...}}` with
		registry/bucket/flow/version + current sync state (UP_TO_DATE,
		LOCALLY_MODIFIED, STALE, SYNC_FAILURE) when the PG is under version
		control, otherwise `{versioned: False, ...}`. Reads VCI from the
		ProcessGroupEntity (`GET /process-groups/{id}`) since NiFi has no bare
		`GET /versions/process-groups/{id}` endpoint.
		"""
		info = nifi.get_version_control_info(process_group_id)
		return _redact_sensitive(info)

	@app.tool()
	async def get_local_modifications(
		process_group_id: str,
		summary: bool = True,
	) -> Dict[str, Any]:
		"""List local modifications on a process group vs its tracked registry version (read-only, NiFi 1.x).

		Equivalent to NiFi UI's "Show Local Changes". Useful for reviewing
		uncommitted edits before saving to registry.

		Args:
		  process_group_id: id of the process group to inspect.
		  summary: when True (default), return a compact digest with total counts,
		    a differenceType histogram, and per-componentType rollup with each
		    affected component's id/name/change_count. When False, return the raw
		    FlowComparisonEntity (redacted) with full per-difference detail.

		Returns a structured error if the process group is not under version control.
		"""
		try:
			raw = nifi.get_local_modifications(process_group_id)
		except NiFiError as e:
			if e.status_code == 404:
				return {
					"error": "process_group_not_under_version_control",
					"process_group_id": process_group_id,
					"message": str(e),
				}
			raise
		raw = _redact_sensitive(raw)
		if not summary:
			return raw
		return _summarize_local_modifications(raw)
	
	@app.tool()
	async def analyze_flow_build_request(user_request: str) -> Dict[str, Any]:
		"""Analyze a user's request to build a NiFi flow and provide guidance.
		
		This tool identifies common flow patterns (SQL to Iceberg, Kafka to S3, etc.)
		and returns the requirements needed to build the flow.
		
		Examples:
		  - "Build a flow from SQL Server to Iceberg"
		  - "I need to move data from Kafka to S3"
		  - "Create a REST API to database pipeline"
		  
		Returns requirements the user needs to provide before building the flow.
		Use this BEFORE attempting to create processors for complex flows.
		"""
		return analyze_flow_request(user_request)
	
	@app.tool()
	async def get_setup_instructions() -> str:
		"""Get comprehensive setup instructions for configuring the NiFi MCP Server.
		
		Use this when:
		  - User asks "how do I configure this?"
		  - Connection errors suggest missing configuration
		  - User needs help with environment variables
		
		Returns detailed setup guide with examples for CDP NiFi and standalone NiFi.
		"""
		return SetupGuide.get_setup_instructions()
	
	@app.tool()
	async def check_configuration() -> Dict[str, Any]:
		"""Check current NiFi MCP Server configuration and validate it.
		
		Use this when:
		  - User asks "is my configuration correct?"
		  - Troubleshooting connection issues
		  - Before attempting to connect to NiFi
		
		Returns validation results with errors and warnings.
		"""
		is_valid, errors, warnings = SetupGuide.validate_current_config()
		return {
			"is_valid": is_valid,
			"errors": errors,
			"warnings": warnings,
			"message": "Configuration is valid" if is_valid else "Configuration has errors"
		}
	
	@app.tool()
	async def get_best_practices_guide() -> str:
		"""Get NiFi flow building best practices guide.
		
		Use this when:
		  - User asks "what are best practices?"
		  - User is building their first flow
		  - User wants to understand proper flow organization
		
		Returns comprehensive guide covering process groups, naming, lifecycle, etc.
		"""
		return NiFiBestPractices.get_best_practices_guide()
	
	@app.tool()
	async def get_recommended_workflow(user_request: str) -> str:
		"""Get recommended step-by-step workflow for building a specific flow.
		
		Use this when:
		  - User asks "how should I build this flow?"
		  - User needs guidance on the order of operations
		  - User is unsure where to start
		
		Args:
		  user_request: Description of the flow the user wants to build
		
		Returns step-by-step workflow with best practices.
		"""
		return NiFiBestPractices.get_recommended_workflow_for_request(user_request)

	# ===== Write Tools (only enabled when NIFI_READONLY=false) =====

	if not readonly:
		@app.tool()
		async def start_processor(processor_id: str, version: int) -> Dict[str, Any]:
			"""Start a processor. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.start_processor(processor_id, version)
			return _redact_sensitive(data)

		@app.tool()
		async def stop_processor(processor_id: str, version: int) -> Dict[str, Any]:
			"""Stop a processor. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.stop_processor(processor_id, version)
			return _redact_sensitive(data)

		@app.tool()
		async def create_processor(
			process_group_id: str,
			processor_type: str,
			name: str,
			position_x: float = 0.0,
			position_y: float = 0.0
		) -> Dict[str, Any]:
			"""Create a new processor in a process group. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Args:
				process_group_id: The ID of the process group to create the processor in
				processor_type: The fully qualified processor type (e.g., 'org.apache.nifi.processors.standard.LogAttribute')
				name: The name for the new processor
				position_x: X coordinate on the canvas (default: 0.0)
				position_y: Y coordinate on the canvas (default: 0.0)
			"""
			data = nifi.create_processor(process_group_id, processor_type, name, position_x, position_y)
			return _redact_sensitive(data)

		@app.tool()
		async def update_processor_config(
			processor_id: str,
			version: int,
			config: Dict[str, Any]
		) -> Dict[str, Any]:
			"""Update processor configuration. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Args:
				processor_id: The processor ID
				version: The current revision version
				config: Configuration object with properties, scheduling strategy, etc.
			"""
			data = nifi.update_processor(processor_id, version, config)
			return _redact_sensitive(data)

		@app.tool()
		async def delete_processor(processor_id: str, version: int) -> Dict[str, Any]:
			"""Delete a processor. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.delete_processor(processor_id, version)
			return _redact_sensitive(data)

		@app.tool()
		async def create_connection(
			process_group_id: str,
			source_id: str,
			source_type: str,
			destination_id: str,
			destination_type: str,
			relationships: str
		) -> Dict[str, Any]:
			"""Create a connection between two components. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Args:
				process_group_id: The process group ID
				source_id: Source component ID
				source_type: Source type (PROCESSOR, INPUT_PORT, OUTPUT_PORT, FUNNEL)
				destination_id: Destination component ID
				destination_type: Destination type (PROCESSOR, INPUT_PORT, OUTPUT_PORT, FUNNEL)
				relationships: Comma-separated list of relationships (e.g., 'success,failure')
			"""
			rel_list = [r.strip() for r in relationships.split(',')]
			data = nifi.create_connection(
				process_group_id, source_id, source_type,
				destination_id, destination_type, rel_list
			)
			return _redact_sensitive(data)

		@app.tool()
		async def delete_connection(connection_id: str, version: int) -> Dict[str, Any]:
			"""Delete a connection. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Note: Connections with flowfiles in the queue cannot be deleted.
			Check queue status with get_connection_details() first, or use empty_connection_queue().
			"""
			data = nifi.delete_connection(connection_id, version)
			return _redact_sensitive(data)

		@app.tool()
		async def empty_connection_queue(connection_id: str) -> Dict[str, Any]:
			"""Drop all flowfiles from a connection's queue. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			⚠️ WARNING: This permanently deletes flowfiles. Use before deleting connections with queued data.
			"""
			data = nifi.empty_connection_queue(connection_id)
			return _redact_sensitive(data)

		@app.tool()
		async def enable_controller_service(service_id: str, version: int) -> Dict[str, Any]:
			"""Enable a controller service. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.enable_controller_service(service_id, version)
			return _redact_sensitive(data)

		@app.tool()
		async def disable_controller_service(service_id: str, version: int) -> Dict[str, Any]:
			"""Disable a controller service. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.disable_controller_service(service_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def create_controller_service(process_group_id: str, service_type: str, name: str) -> Dict[str, Any]:
			"""Create a controller service in a process group. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Common service types:
			  - org.apache.nifi.dbcp.DBCPConnectionPool (Database connections)
			  - org.apache.nifi.json.JsonRecordSetWriter (JSON output)
			  - org.apache.nifi.avro.AvroRecordSetWriter (Avro output)
			  - org.apache.nifi.csv.CSVRecordSetWriter (CSV output)
			  - org.apache.nifi.json.JsonTreeReader (JSON input)
			  - org.apache.nifi.avro.AvroReader (Avro input)
			  - org.apache.nifi.csv.CSVReader (CSV input)
			
			Returns the created service with ID for configuration.
			"""
			data = nifi.create_controller_service(process_group_id, service_type, name)
			return _redact_sensitive(data)
		
		@app.tool()
		async def update_controller_service_properties(service_id: str, version: int, properties: Dict[str, str]) -> Dict[str, Any]:
			"""Update controller service properties. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Note: Service must be in DISABLED state to update properties.
			Use get_controller_service() to see available properties and current values.
			"""
			data = nifi.update_controller_service(service_id, version, properties)
			return _redact_sensitive(data)
		
	@app.tool()
	async def get_controller_service_details(service_id: str) -> Dict[str, Any]:
		"""Get detailed controller service information including properties and state.
		
		Use this to check current configuration before updates.
		"""
		data = nifi.get_controller_service(service_id)
		return _redact_sensitive(data)
	
	@app.tool()
	async def find_controller_services_by_type(process_group_id: str, service_type: str) -> Dict[str, Any]:
		"""Find controller services by type to check if they already exist (read-only).
		
		Use this BEFORE creating controller services to avoid 409 Conflict errors.
		
		Args:
			process_group_id: Process group ID (use "root" for controller-level)
			service_type: Full service type name (e.g., "org.apache.nifi.distributed.cache.server.map.DistributedMapCacheServer")
		
		Returns list of matching services with their IDs, names, and states.
		
		Example:
			Before creating a DistributedMapCacheServer, check if one already exists:
			find_controller_services_by_type("root", "org.apache.nifi.distributed.cache.server.map.DistributedMapCacheServer")
		"""
		pg_id = None if process_group_id.lower() == "root" else process_group_id
		matches = nifi.find_controller_services_by_type(pg_id, service_type)
		
		# Simplify output for LLM consumption
		simplified = []
		for svc in matches:
			component = svc.get("component", {})
			simplified.append({
				"id": component.get("id"),
				"name": component.get("name"),
				"type": component.get("type"),
				"state": component.get("state"),
				"version": svc.get("revision", {}).get("version")
			})
		
		return {
			"count": len(simplified),
			"services": simplified,
			"message": f"Found {len(simplified)} existing service(s) of type {service_type}"
		}
	
	if not readonly:
		@app.tool()
		async def delete_controller_service(service_id: str, version: int) -> Dict[str, Any]:
			"""Delete a controller service. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Prerequisites:
			  - Service must be DISABLED
			  - No processors can reference this service
			"""
			data = nifi.delete_controller_service(service_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def start_new_flow(flow_name: str, parent_pg_id: str = None) -> Dict[str, Any]:
			"""Start a new NiFi flow following best practices. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			🌟 RECOMMENDED WAY to start building flows!
			
			This tool automatically:
			  1. Creates a process group for your flow (best practice!)
			  2. Returns the group ID for adding components
			  3. Provides next steps guidance
			
			Use this INSTEAD of creating processors directly on root canvas.
			
			Args:
			  flow_name: Descriptive name for your flow (e.g., "ETL Pipeline", "Kafka Integration")
			  parent_pg_id: Optional parent process group (defaults to root)
			
			Example: start_new_flow("Data Ingestion Pipeline")
			"""
			smart_builder = SmartFlowBuilder(nifi)
			result = smart_builder.start_new_flow(flow_name, parent_pg_id)
			return _redact_sensitive(result)
		
		@app.tool()
		async def create_process_group(parent_id: str, name: str, position_x: float = 0.0, position_y: float = 0.0) -> Dict[str, Any]:
			"""Create a process group (folder) for organizing flows. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Process groups allow you to organize flows into logical sections:
			  - Separate dev/test/prod environments
			  - Group related processors
			  - Create modular, reusable flow components
			
			💡 TIP: Consider using start_new_flow() instead - it follows best practices automatically!
			
			Returns the created process group with ID for adding processors.
			"""
			data = nifi.create_process_group(parent_id, name, position_x, position_y)
			return _redact_sensitive(data)
		
		@app.tool()
		async def update_process_group_name(pg_id: str, version: int, name: str) -> Dict[str, Any]:
			"""Rename a process group. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.update_process_group(pg_id, version, name)
			return _redact_sensitive(data)
		
		@app.tool()
		async def delete_process_group(pg_id: str, version: int) -> Dict[str, Any]:
			"""Delete a process group. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Prerequisites:
			  - Process group must be empty (no processors, connections, or child groups)
			  - All components must be stopped
			
			Use this to clean up empty organizational groups.
			"""
			data = nifi.delete_process_group(pg_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def create_input_port(pg_id: str, name: str, position_x: float = 0.0, position_y: float = 0.0) -> Dict[str, Any]:
			"""Create an input port for inter-process-group communication. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Input ports allow child process groups to receive data from parent groups.
			Connect processors in parent group to this port to send data into the child group.
			"""
			data = nifi.create_input_port(pg_id, name, position_x, position_y)
			return _redact_sensitive(data)
		
		@app.tool()
		async def create_output_port(pg_id: str, name: str, position_x: float = 0.0, position_y: float = 0.0) -> Dict[str, Any]:
			"""Create an output port for inter-process-group communication. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Output ports allow child process groups to send data to parent groups.
			Connect processors to this port, then connect the port to processors in parent group.
			"""
			data = nifi.create_output_port(pg_id, name, position_x, position_y)
			return _redact_sensitive(data)
		
		@app.tool()
		async def update_input_port(port_id: str, version: int, name: str) -> Dict[str, Any]:
			"""Update (rename) an input port. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.update_input_port(port_id, version, name)
			return _redact_sensitive(data)
		
		@app.tool()
		async def update_output_port(port_id: str, version: int, name: str) -> Dict[str, Any]:
			"""Update (rename) an output port. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.update_output_port(port_id, version, name)
			return _redact_sensitive(data)
		
		@app.tool()
		async def delete_input_port(port_id: str, version: int) -> Dict[str, Any]:
			"""Delete an input port. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.delete_input_port(port_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def delete_output_port(port_id: str, version: int) -> Dict[str, Any]:
			"""Delete an output port. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.delete_output_port(port_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def get_parameter_context_details(context_id: str) -> Dict[str, Any]:
			"""Get parameter context with all parameters."""
			data = nifi.get_parameter_context(context_id)
			return _redact_sensitive(data)
		
		@app.tool()
		async def create_parameter_context(name: str, description: str = "", parameters: str = "[]") -> Dict[str, Any]:
			"""Create a parameter context for environment-specific configuration. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Parameters should be JSON array of objects with 'name', 'value', 'sensitive' fields.
			Example: '[{"name":"db.host","value":"localhost","sensitive":false}]'
			
			Use cases:
			  - Store database connection strings
			  - Environment-specific URLs
			  - API keys (use sensitive:true)
			"""
			import json
			params_list = json.loads(parameters) if parameters != "[]" else None
			data = nifi.create_parameter_context(name, description, params_list)
			return _redact_sensitive(data)
		
		@app.tool()
		async def update_parameter_context(context_id: str, version: int, name: str = None, parameters: str = None) -> Dict[str, Any]:
			"""Update parameter context. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Parameters should be JSON array if provided.
			"""
			import json
			params_list = json.loads(parameters) if parameters else None
			data = nifi.update_parameter_context(context_id, version, name, None, params_list)
			return _redact_sensitive(data)
		
		@app.tool()
		async def delete_parameter_context(context_id: str, version: int) -> Dict[str, Any]:
			"""Delete a parameter context. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Note: Context must not be referenced by any process groups.
			"""
			data = nifi.delete_parameter_context(context_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def start_input_port(port_id: str, version: int) -> Dict[str, Any]:
			"""Start an input port to enable data flow. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Ports are created in STOPPED state by default and must be started to receive data.
			"""
			data = nifi.start_input_port(port_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def stop_input_port(port_id: str, version: int) -> Dict[str, Any]:
			"""Stop an input port to disable data flow. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.stop_input_port(port_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def start_output_port(port_id: str, version: int) -> Dict[str, Any]:
			"""Start an output port to enable data flow. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			Ports are created in STOPPED state by default and must be started to send data.
			"""
			data = nifi.start_output_port(port_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def stop_output_port(port_id: str, version: int) -> Dict[str, Any]:
			"""Stop an output port to disable data flow. **WRITE OPERATION** - Requires NIFI_READONLY=false."""
			data = nifi.stop_output_port(port_id, version)
			return _redact_sensitive(data)
		
		@app.tool()
		async def apply_parameter_context_to_process_group(pg_id: str, pg_version: int, context_id: str) -> Dict[str, Any]:
			"""Apply a parameter context to a process group. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			This enables the process group and its processors to reference parameters using #{param_name} syntax.
			
			Example workflow:
			  1. Create parameter context with db credentials
			  2. Apply context to process group
			  3. Use #{db.host}, #{db.password} in processor properties
			"""
			data = nifi.apply_parameter_context_to_process_group(pg_id, pg_version, context_id)
			return _redact_sensitive(data)
		
		@app.tool()
		async def start_all_processors_in_group(pg_id: str) -> Dict[str, Any]:
			"""Start ALL processors in a process group at once. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			This is a BULK operation that starts all processors simultaneously, much faster than starting individually.
			
			Returns counts of:
			  - started: Successfully started processors
			  - already_running: Processors that were already running
			  - failed: Processors that failed to start (with error messages)
			
			Use case: "Start all processors in my ETL group"
			"""
			data = nifi.start_all_processors_in_group(pg_id)
			return _redact_sensitive(data)
		
		@app.tool()
		async def stop_all_processors_in_group(pg_id: str) -> Dict[str, Any]:
			"""Stop ALL processors in a process group at once. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			This is a BULK operation that stops all processors simultaneously, much faster than stopping individually.
			
			Returns counts of:
			  - stopped: Successfully stopped processors
			  - already_stopped: Processors that were already stopped
			  - failed: Processors that failed to stop (with error messages)
			
			Use case: "Stop all processors before making changes"
			"""
			data = nifi.stop_all_processors_in_group(pg_id)
			return _redact_sensitive(data)
		
		@app.tool()
		async def enable_all_controller_services_in_group(pg_id: str) -> Dict[str, Any]:
			"""Enable ALL controller services in a process group at once. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			This is a BULK operation that enables all services simultaneously.
			
			Returns counts of:
			  - enabled: Successfully enabled services
			  - already_enabled: Services that were already enabled
			  - failed: Services that failed to enable (with error messages)
			
			Use case: "Enable all services before starting flow"
			"""
			data = nifi.enable_all_controller_services_in_group(pg_id)
			return _redact_sensitive(data)
		
		@app.tool()
		async def terminate_processor(processor_id: str, version: int) -> Dict[str, Any]:
			"""Forcefully terminate a stuck processor. **WRITE OPERATION** - Requires NIFI_READONLY=false.
			
			⚠️ WARNING: Last-resort operation for processors that won't stop normally!
			
			Use only when:
			  - Processor is stuck and not responding
			  - Normal stop command doesn't work
			  - Processor threads need to be killed
			
			The operation first tries a normal stop, only terminates if that fails.
			
			Use case: "My processor is stuck and won't stop, force terminate it"
			"""
			data = nifi.terminate_processor(processor_id, version)
			return _redact_sensitive(data)
	
	# Read-only health monitoring tool (available even in readonly mode)
	@app.tool()
	async def get_flow_health_status(pg_id: str) -> Dict[str, Any]:
		"""Get comprehensive health status of a process group and all its components.
		
		Returns detailed health information:
		  - Processor status (running/stopped/invalid/disabled counts)
		  - Controller service status (enabled/disabled/invalid counts)
		  - Connection queue status (queued data, backpressure)
		  - Recent bulletins and errors
		  - Overall health assessment (HEALTHY | DEGRADED | UNHEALTHY)
		
		Use cases:
		  - "Is my flow healthy?"
		  - "Show me flow status"
		  - "What's broken in my pipeline?"
		  - "Check for errors in my data ingestion group"
		"""
		data = nifi.get_flow_health_status(pg_id)
		return _redact_sensitive(data)

	return app


async def run_stdio() -> None:
	# For FastMCP, prefer the built-in stdio runner
	config = ServerConfig()
	nifi = build_client(config)
	server = create_server(nifi, readonly=config.readonly)
	# run() is synchronous; call the async flavor directly
	await server.run_stdio_async()


def main() -> None:
	transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
	if transport != "stdio":
		# Defer to FastMCP synchronous run helper for other transports when added
		config = ServerConfig()
		nifi = build_client(config)
		server = create_server(nifi, readonly=config.readonly)
		server.run(transport=transport)
		return
	anyio.run(run_stdio)


if __name__ == "__main__":
	main()


