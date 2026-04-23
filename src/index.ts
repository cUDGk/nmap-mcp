#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { z } from "zod";
import { XMLParser } from "fast-xml-parser";

const NMAP = process.env.NMAP_PATH ?? (process.platform === "win32"
  ? "C:/Program Files (x86)/Nmap/nmap.exe"
  : "nmap");
const DEFAULT_TIMEOUT = parseInt(process.env.NMAP_TIMEOUT ?? "600000", 10);
const MAX_STDERR = 16384;

function killProc(proc: ChildProcess): void {
  if (!proc.pid) return;
  if (process.platform === "win32") {
    try { execFileSync("taskkill", ["/F", "/T", "/PID", String(proc.pid)], { stdio: "ignore" }); return; } catch {}
  }
  try { proc.kill("SIGKILL"); } catch {}
}

type RunResult = {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  duration_ms: number;
  timed_out: boolean;
};

function runNmap(args: string[], opts: { timeout?: number } = {}): Promise<RunResult> {
  const t0 = Date.now();
  const to = opts.timeout ?? DEFAULT_TIMEOUT;
  return new Promise((res) => {
    const proc = spawn(NMAP, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "", timedOut = false;
    const timer = setTimeout(() => { timedOut = true; killProc(proc); }, to);
    proc.stdout!.on("data", (c) => { stdout += c.toString("utf8"); });
    proc.stderr!.on("data", (c) => {
      stderr += c.toString("utf8");
      if (stderr.length > MAX_STDERR * 2) stderr = stderr.slice(-MAX_STDERR);
    });
    proc.on("error", (err) => {
      clearTimeout(timer);
      res({ exit_code: null, stdout, stderr: `spawn error: ${err.message}. Is nmap at "${NMAP}"?`, duration_ms: Date.now() - t0, timed_out: false });
    });
    proc.on("close", (code) => {
      clearTimeout(timer);
      if (stderr.length > MAX_STDERR) stderr = stderr.slice(-MAX_STDERR);
      res({ exit_code: code, stdout, stderr, duration_ms: Date.now() - t0, timed_out: timedOut });
    });
  });
}

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "",
  parseTagValue: true,
  parseAttributeValue: true,
  isArray: (name) => ["host", "port", "address", "hostname", "script", "osmatch"].includes(name),
});

function parseNmapXml(xml: string) {
  const doc = xmlParser.parse(xml);
  const run = doc.nmaprun;
  if (!run) return { error: "invalid nmap xml", raw: xml.slice(0, 2000) };
  const hosts = (run.host ?? []).map((h: any) => {
    const addresses = (h.address ?? []).map((a: any) => ({ addr: a.addr, type: a.addrtype, vendor: a.vendor }));
    const hostnames = (h.hostnames?.hostname ?? []).map((hn: any) => ({ name: hn.name, type: hn.type }));
    const status = h.status && { state: h.status.state, reason: h.status.reason };
    const ports = (h.ports?.port ?? []).map((p: any) => ({
      protocol: p.protocol,
      port: Number(p.portid),
      state: p.state?.state,
      state_reason: p.state?.reason,
      service_name: p.service?.name,
      service_product: p.service?.product,
      service_version: p.service?.version,
      service_extrainfo: p.service?.extrainfo,
      service_method: p.service?.method,
      service_conf: p.service?.conf,
      scripts: (p.script ?? []).map((s: any) => ({ id: s.id, output: s.output })),
    }));
    const osmatches = (h.os?.osmatch ?? []).map((o: any) => ({
      name: o.name,
      accuracy: Number(o.accuracy),
      family: o.osclass?.osfamily ?? o.osclass?.[0]?.osfamily,
      gen: o.osclass?.osgen ?? o.osclass?.[0]?.osgen,
    }));
    return {
      status,
      addresses,
      hostnames,
      ports,
      os_matches: osmatches,
      uptime: h.uptime && { seconds: Number(h.uptime.seconds), last_boot: h.uptime.lastboot },
      distance: h.distance?.value,
    };
  });
  const up = hosts.filter((h: any) => h.status?.state === "up").length;
  const stats = {
    scanner: run.scanner,
    args: run.args,
    start: Number(run.start),
    start_str: run.startstr,
    elapsed: run.runstats?.finished?.elapsed,
    summary: run.runstats?.finished?.summary,
    hosts_total: hosts.length,
    hosts_up: up,
    hosts_down: hosts.length - up,
  };
  return { stats, hosts };
}

function buildArgs(base: string[], opts: {
  target?: string;
  ports?: string;
  top_ports?: number;
  service_detect?: boolean;
  version_intensity?: number;
  os_detect?: boolean;
  script?: string;
  script_args?: string;
  timing?: number;
  host_discovery?: "default" | "skip_ping" | "ping_only";
  udp?: boolean;
  tcp_syn?: boolean;
  tcp_connect?: boolean;
  max_rate?: number;
  min_rate?: number;
  reason?: boolean;
  open_only?: boolean;
  resolve_dns?: boolean;
  traceroute?: boolean;
  extra_args?: string[];
}): string[] {
  const args: string[] = [...base];
  if (opts.host_discovery === "skip_ping") args.push("-Pn");
  else if (opts.host_discovery === "ping_only") args.push("-sn");
  if (opts.udp) args.push("-sU");
  if (opts.tcp_syn) args.push("-sS");
  if (opts.tcp_connect) args.push("-sT");
  if (opts.ports) args.push("-p", opts.ports);
  if (opts.top_ports) args.push("--top-ports", String(opts.top_ports));
  if (opts.service_detect) args.push("-sV");
  if (opts.version_intensity !== undefined) args.push("--version-intensity", String(opts.version_intensity));
  if (opts.os_detect) args.push("-O");
  if (opts.script) args.push("--script", opts.script);
  if (opts.script_args) args.push("--script-args", opts.script_args);
  if (opts.timing !== undefined) args.push(`-T${opts.timing}`);
  if (opts.max_rate !== undefined) args.push("--max-rate", String(opts.max_rate));
  if (opts.min_rate !== undefined) args.push("--min-rate", String(opts.min_rate));
  if (opts.reason) args.push("--reason");
  if (opts.open_only) args.push("--open");
  if (opts.traceroute) args.push("--traceroute");
  if (opts.resolve_dns === false) args.push("-n");
  if (opts.resolve_dns === true) args.push("-R");
  if (opts.extra_args) args.push(...opts.extra_args);
  args.push("-oX", "-");
  if (opts.target) args.push(opts.target);
  return args;
}

function textContent(data: unknown) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text" as const, text }] };
}

function errContent(msg: string) {
  return { content: [{ type: "text" as const, text: msg }], isError: true };
}

function buildResponse(r: RunResult, parsed?: any) {
  const body: any = { exit_code: r.exit_code, duration_ms: r.duration_ms, timed_out: r.timed_out };
  if (parsed) Object.assign(body, parsed);
  if (r.stderr) body.stderr = r.stderr;
  const resp = textContent(body);
  if (r.exit_code !== 0) (resp as any).isError = true;
  return resp;
}

const server = new McpServer({ name: "nmap", version: "0.1.0" });

server.tool(
  "nmap",
  `Invoke nmap with XML output (-oX -) and parse it into structured JSON.

Actions:
- discover: ping scan only (-sn). Fast host enumeration. No ports.
- scan: port scan. Specify 'ports' (e.g. "22,80,443" or "1-1024") or 'top_ports' (e.g. 100).
  Optional service_detect (-sV), os_detect (-O, needs admin/root), script (NSE).
- services: scan + service_detect + default scripts shortcut.
- os_detect: -O + -sV. Typically needs admin (raw sockets / ICMP).
- run: raw args escape hatch. args[] passed directly to nmap; XML parsing still attempted.
- version: nmap --version.

Options carried across actions:
- target: host / CIDR / range / hostname (e.g. "192.168.1.0/24", "scanme.nmap.org", "10.0.0.1-20")
- host_discovery: "default" | "skip_ping" (add -Pn) | "ping_only" (add -sn)
- tcp_syn (-sS, needs raw), tcp_connect (-sT, no privilege required), udp (-sU)
- timing: 0..5 (-T0 paranoid .. -T5 insane; default 3)
- max_rate / min_rate: packets/sec throttling
- reason (add --reason), open_only (--open), resolve_dns (false→-n, true→-R)
- script / script_args: NSE scripts
- extra_args: anything else

Output: { stats, hosts[] }. hosts[] includes addresses, hostnames, ports[] with state + service detection + NSE script outputs.

Security note: only scan networks you are authorized to. OS detection (-O) and SYN scan (-sS) need admin/root on most systems.`,
  {
    action: z.enum(["discover", "scan", "services", "os_detect", "arp", "vuln", "run", "from_xml", "version"]).describe("Action"),
    target: z.string().optional().describe("Target: host / CIDR / range / hostname"),
    ports: z.string().optional().describe("Ports (e.g. '22,80,443' or '1-1024')"),
    top_ports: z.number().int().positive().optional().describe("Scan top N ports"),
    service_detect: z.boolean().optional().describe("-sV"),
    version_intensity: z.number().int().min(0).max(9).optional().describe("--version-intensity N"),
    os_detect: z.boolean().optional().describe("-O"),
    script: z.string().optional().describe("--script <category|name>"),
    script_args: z.string().optional().describe("--script-args ..."),
    timing: z.number().int().min(0).max(5).optional().describe("-T<0..5>"),
    host_discovery: z.enum(["default", "skip_ping", "ping_only"]).optional(),
    udp: z.boolean().optional().describe("-sU"),
    tcp_syn: z.boolean().optional().describe("-sS (needs privileges)"),
    tcp_connect: z.boolean().optional().describe("-sT"),
    max_rate: z.number().optional().describe("--max-rate packets/sec"),
    min_rate: z.number().optional().describe("--min-rate packets/sec"),
    reason: z.boolean().optional().describe("--reason"),
    open_only: z.boolean().optional().describe("--open"),
    resolve_dns: z.boolean().optional().describe("DNS resolution (false → -n, true → -R)"),
    traceroute: z.boolean().optional().describe("--traceroute"),
    extra_args: z.array(z.string()).optional().describe("Extra nmap args"),
    args: z.array(z.string()).optional().describe("run: raw args (still add -oX -)"),
    timeout: z.number().optional().describe("Per-call timeout ms (default NMAP_TIMEOUT=600000)"),
    save_xml: z.string().optional().describe("If set, write raw nmap XML to this path"),
    xml_path: z.string().optional().describe("from_xml: path to existing nmap XML file"),
  },
  async (p) => {
    try {
      if (p.action === "version") {
        const r = await runNmap(["--version"], { timeout: 10000 });
        return textContent({
          version: (r.stdout.split(/\r?\n/)[0] ?? "").trim(),
          stdout: r.stdout,
          exit_code: r.exit_code,
        });
      }
      if (p.action === "from_xml") {
        if (!p.xml_path) return errContent("from_xml requires 'xml_path'");
        const abs = resolvePath(p.xml_path);
        const xml = readFileSync(abs, "utf8");
        const parsed = parseNmapXml(xml);
        return textContent({ source_path: abs, ...parsed });
      }
      if (p.action === "run") {
        if (!p.args) return errContent("run requires 'args'");
        const args = [...p.args];
        if (!args.includes("-oX")) args.push("-oX", "-");
        const r = await runNmap(args, { timeout: p.timeout });
        let parsed: any;
        try { parsed = parseNmapXml(r.stdout); } catch { parsed = undefined; }
        if (p.save_xml && r.stdout) writeFileSync(resolvePath(p.save_xml), r.stdout, "utf8");
        return buildResponse(r, parsed);
      }
      if (!p.target) return errContent(`${p.action} requires 'target'`);

      let base: string[];
      const opts = { ...p } as any;
      if (p.action === "discover") {
        base = [];
        opts.host_discovery = "ping_only";
      } else if (p.action === "arp") {
        base = [];
        opts.host_discovery = "ping_only";
        opts.extra_args = [...(opts.extra_args ?? []), "-PR"];
      } else if (p.action === "services") {
        base = [];
        opts.service_detect = true;
        if (!opts.script) opts.script = "default";
      } else if (p.action === "os_detect") {
        base = [];
        opts.os_detect = true;
        opts.service_detect = true;
      } else if (p.action === "vuln") {
        base = [];
        opts.service_detect = true;
        opts.script = opts.script ? `${opts.script},vuln` : "vuln";
      } else {
        base = [];
      }
      const args = buildArgs(base, opts);
      const r = await runNmap(args, { timeout: p.timeout });
      if (p.save_xml && r.stdout) {
        try { writeFileSync(resolvePath(p.save_xml), r.stdout, "utf8"); } catch {}
      }
      if (r.exit_code !== 0 && !r.stdout.trim()) {
        return buildResponse(r);
      }
      let parsed: any;
      try { parsed = parseNmapXml(r.stdout); }
      catch (e: any) { parsed = { xml_parse_error: e.message, raw: r.stdout.slice(0, 2000) }; }
      return buildResponse(r, parsed);
    } catch (err: any) {
      return errContent(`Error: ${err?.message ?? String(err)}`);
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => { console.error("Fatal:", err); process.exit(1); });
