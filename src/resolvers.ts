import { Resolver } from "node:dns/promises";
import {
  discoveryError,
  errorLogFields,
  getErrorCode,
  getErrorMessage,
  logDebug,
  logWarn,
} from "./observability.ts";
import type {
  CompositeResolverStrategy,
  DetailedResolverAttempt,
  DetailedResolverResult,
  DiscoveryErrorCode,
  DiscoveryLogger,
  LoggerRedactionOptions,
  ManifestTlsaRecord,
  ResolverRecordType,
  ResolverStatus,
  TlsaResolver,
  TxtResolver,
} from "./types.ts";

const NO_RECORD_CODES = new Set(["ENODATA", "ENOTFOUND", "NOTFOUND"]);
const DEFAULT_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const DEFAULT_DOH_TIMEOUT_MS = 5_000;
const DNS_TYPE = {
  TXT: 16,
  TLSA: 52,
} as const;

type ResolverCandidate = TxtResolver & Partial<TlsaResolver>;
type NodeDnsResolverWithOptionalTlsa = Resolver & {
  resolveTlsa?: (name: string) => Promise<ManifestTlsaRecord[]>;
};

interface CompositeResolverOptions {
  strategy?: CompositeResolverStrategy;
  quorum?: number;
  name?: string;
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

interface DohResolverOptions {
  endpoint?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
  name?: string;
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

interface DotResolverOptions {
  server: string;
  port?: number;
  name?: string;
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

interface FetchLikeResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

type FetchLike = (
  input: string,
  init?: {
    headers?: Record<string, string>;
    signal?: AbortSignal;
  },
) => Promise<FetchLikeResponse>;

interface DohJsonAnswer {
  type?: number;
  data?: string;
}

export class MockResolver implements TxtResolver, TlsaResolver {
  readonly name: string;
  readonly records: Map<string, string[]>;
  readonly tlsaRecords: Map<string, ManifestTlsaRecord[]>;

  constructor(
    records: Record<string, string[]> | Map<string, string[]>,
    options: {
      name?: string;
      tlsaRecords?: Record<string, ManifestTlsaRecord[]> | Map<string, ManifestTlsaRecord[]>;
      logger?: DiscoveryLogger;
      redaction?: LoggerRedactionOptions;
    } = {},
  ) {
    const entries = records instanceof Map ? records.entries() : Object.entries(records);
    const tlsaEntries =
      options.tlsaRecords instanceof Map
        ? options.tlsaRecords.entries()
        : Object.entries(options.tlsaRecords ?? {});

    this.name = options.name ?? "mock";
    this.records = new Map([...entries].map(([name, values]) => [normalizeDnsName(name), values]));
    this.tlsaRecords = new Map(
      [...tlsaEntries].map(([name, values]) => [normalizeDnsName(name), values]),
    );
  }

  async resolveTxt(name: string): Promise<string[]> {
    const result = await this.resolveTxtDetailed(name);
    return unwrapDetailedResult(result);
  }

  async resolveTxtDetailed(name: string): Promise<DetailedResolverResult<string>> {
    const normalizedName = normalizeDnsName(name);
    const records = this.records.get(normalizedName) ?? [];

    return createDetailedResult({
      name: normalizedName,
      type: "TXT",
      resolver: this.name,
      records,
    });
  }

  async resolveTlsa(hostname: string, port: number): Promise<ManifestTlsaRecord[]> {
    const result = await this.resolveTlsaDetailed(hostname, port);
    return unwrapDetailedResult(result);
  }

  async resolveTlsaDetailed(
    hostname: string,
    port: number,
  ): Promise<DetailedResolverResult<ManifestTlsaRecord>> {
    const recordName = createTlsaRecordName(hostname, port);
    const records = this.tlsaRecords.get(recordName) ?? [];

    return createDetailedResult({
      name: recordName,
      type: "TLSA",
      resolver: this.name,
      records,
    });
  }
}

export class DnsResolver implements TxtResolver, TlsaResolver {
  readonly name: string;
  private readonly resolver: Resolver;
  private readonly logger: DiscoveryLogger | undefined;
  private readonly redaction: LoggerRedactionOptions | undefined;

  constructor(
    server?: string,
    name = server ? `dns:${server}` : "dns",
    options: { logger?: DiscoveryLogger; redaction?: LoggerRedactionOptions } = {},
  ) {
    this.name = name;
    this.resolver = new Resolver();
    this.logger = options.logger;
    this.redaction = options.redaction;

    if (server) {
      this.resolver.setServers([server]);
    }
  }

  async resolveTxt(name: string): Promise<string[]> {
    const result = await this.resolveTxtDetailed(name);
    return unwrapDetailedResult(result);
  }

  async resolveTxtDetailed(name: string): Promise<DetailedResolverResult<string>> {
    const normalizedName = normalizeDnsName(name);
    logDebug(this.logger, "Resolving TXT records", { name: normalizedName, resolver: this.name }, this.redaction);

    try {
      const answers = await this.resolver.resolveTxt(normalizedName);
      return createDetailedResult({
        name: normalizedName,
        type: "TXT",
        resolver: this.name,
        records: answers.map((segments) => segments.join("")),
      });
    } catch (error) {
      logWarn(
        this.logger,
        "TXT lookup failed",
        { name: normalizedName, resolver: this.name, ...errorLogFields(error, "RESOLVER_LOOKUP_ERROR") },
        this.redaction,
      );
      return createLookupErrorResult(normalizedName, "TXT", this.name, error);
    }
  }

  async resolveTlsa(hostname: string, port: number): Promise<ManifestTlsaRecord[]> {
    const result = await this.resolveTlsaDetailed(hostname, port);
    return unwrapDetailedResult(result);
  }

  async resolveTlsaDetailed(
    hostname: string,
    port: number,
  ): Promise<DetailedResolverResult<ManifestTlsaRecord>> {
    const recordName = createTlsaRecordName(hostname, port);
    logDebug(this.logger, "Resolving TLSA records", { name: recordName, resolver: this.name }, this.redaction);
    const resolveTlsa = (this.resolver as NodeDnsResolverWithOptionalTlsa).resolveTlsa;

    if (typeof resolveTlsa !== "function") {
      const error = discoveryError(
        "RESOLVER_UNSUPPORTED",
        "Node.js 22.15 or newer is required for built-in TLSA support. Use a DoH resolver, custom TLSA resolver, or disable DANE.",
      );
      logWarn(
        this.logger,
        "TLSA lookup unsupported",
        { name: recordName, resolver: this.name, ...errorLogFields(error, "RESOLVER_UNSUPPORTED") },
        this.redaction,
      );
      return createDetailedResult({
        name: recordName,
        type: "TLSA",
        resolver: this.name,
        status: "lookup-error",
        code: "RESOLVER_UNSUPPORTED",
        records: [],
        error: error.message,
      });
    }

    try {
      const records = (await resolveTlsa.call(this.resolver, recordName)) as ManifestTlsaRecord[];
      return createDetailedResult({
        name: recordName,
        type: "TLSA",
        resolver: this.name,
        records,
      });
    } catch (error) {
      logWarn(
        this.logger,
        "TLSA lookup failed",
        { name: recordName, resolver: this.name, ...errorLogFields(error, "RESOLVER_LOOKUP_ERROR") },
        this.redaction,
      );
      return createLookupErrorResult(recordName, "TLSA", this.name, error);
    }
  }
}

export class CompositeResolver implements TxtResolver, TlsaResolver {
  readonly name: string;
  private readonly resolvers: ResolverCandidate[];
  private readonly strategy: CompositeResolverStrategy;
  private readonly quorum?: number;
  private readonly logger: DiscoveryLogger | undefined;
  private readonly redaction: LoggerRedactionOptions | undefined;

  constructor(resolvers: ResolverCandidate[], options: CompositeResolverOptions = {}) {
    if (resolvers.length === 0) {
      throw new Error("CompositeResolver requires at least one resolver.");
    }

    this.resolvers = resolvers;
    this.strategy = options.strategy ?? "first-success";
    this.name = options.name ?? `composite:${this.strategy}`;
    this.logger = options.logger;
    this.redaction = options.redaction;

    if (options.quorum !== undefined) {
      if (!Number.isInteger(options.quorum) || options.quorum < 1) {
        throw new Error("CompositeResolver quorum must be a positive integer.");
      }

      this.quorum = options.quorum;
    }
  }

  async resolveTxt(name: string): Promise<string[]> {
    const result = await this.resolveTxtDetailed(name);
    return unwrapDetailedResult(result);
  }

  async resolveTxtDetailed(name: string): Promise<DetailedResolverResult<string>> {
    const normalizedName = normalizeDnsName(name);

    return this.resolveDetailed(normalizedName, "TXT", (resolver, index) =>
      resolveTxtAttempt(resolver, normalizedName, index),
    );
  }

  async resolveTlsa(hostname: string, port: number): Promise<ManifestTlsaRecord[]> {
    const result = await this.resolveTlsaDetailed(hostname, port);
    return unwrapDetailedResult(result);
  }

  async resolveTlsaDetailed(
    hostname: string,
    port: number,
  ): Promise<DetailedResolverResult<ManifestTlsaRecord>> {
    const recordName = createTlsaRecordName(hostname, port);

    return this.resolveDetailed(recordName, "TLSA", (resolver, index) =>
      resolveTlsaAttempt(resolver, hostname, port, index),
    );
  }

  private async resolveDetailed<TRecord>(
    name: string,
    type: ResolverRecordType,
    resolveAttempt: (
      resolver: ResolverCandidate,
      index: number,
    ) => Promise<DetailedResolverAttempt<TRecord>>,
  ): Promise<DetailedResolverResult<TRecord>> {
    if (this.strategy === "first-success") {
      return resolveFirstSuccess(
        name,
        type,
        this.name,
        this.resolvers,
        resolveAttempt,
        this.logger,
        this.redaction,
      );
    }

    const attempts = await Promise.all(this.resolvers.map(resolveAttempt));

    if (this.strategy === "strict-consensus") {
      return resolveStrictConsensus(name, type, this.name, attempts, this.logger, this.redaction);
    }

    return resolveQuorum(
      name,
      type,
      this.name,
      attempts,
      this.quorum ?? Math.floor(this.resolvers.length / 2) + 1,
      this.logger,
      this.redaction,
    );
  }
}

export class DohResolver implements TxtResolver, TlsaResolver {
  readonly name: string;
  private readonly endpoint: string;
  private readonly fetch: FetchLike;
  private readonly timeoutMs: number;
  private readonly logger: DiscoveryLogger | undefined;
  private readonly redaction: LoggerRedactionOptions | undefined;

  constructor(options: DohResolverOptions = {}) {
    this.endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;
    this.fetch = options.fetch ?? (globalThis.fetch as FetchLike);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_DOH_TIMEOUT_MS;
    this.name = options.name ?? `doh:${this.endpoint}`;
    this.logger = options.logger;
    this.redaction = options.redaction;

    if (!this.fetch) {
      throw new Error("DohResolver requires native fetch or an injected fetch implementation.");
    }
  }

  async resolveTxt(name: string): Promise<string[]> {
    const result = await this.resolveTxtDetailed(name);
    return unwrapDetailedResult(result);
  }

  async resolveTxtDetailed(name: string): Promise<DetailedResolverResult<string>> {
    const normalizedName = normalizeDnsName(name);
    const result = await this.queryDoh(normalizedName, "TXT");

    if (result.status !== "ok") {
      return result;
    }

    return {
      ...result,
      records: result.records.map(parseDohTxtAnswerData),
    };
  }

  async resolveTlsa(hostname: string, port: number): Promise<ManifestTlsaRecord[]> {
    const result = await this.resolveTlsaDetailed(hostname, port);
    return unwrapDetailedResult(result);
  }

  async resolveTlsaDetailed(
    hostname: string,
    port: number,
  ): Promise<DetailedResolverResult<ManifestTlsaRecord>> {
    const recordName = createTlsaRecordName(hostname, port);
    const result = await this.queryDoh(recordName, "TLSA");

    if (result.status !== "ok") {
      return createDetailedResult<ManifestTlsaRecord>({
        name: result.name,
        type: "TLSA",
        resolver: result.resolver ?? this.name,
        status: result.status,
        ...(result.code ? { code: result.code } : {}),
        records: [],
        ...(result.error ? { error: result.error } : {}),
      });
    }

    return createDetailedResult({
      name: result.name,
      type: "TLSA",
      resolver: result.resolver ?? this.name,
      records: result.records.map(parseDohTlsaAnswerData),
    });
  }

  private async queryDoh(
    name: string,
    type: ResolverRecordType,
  ): Promise<DetailedResolverResult<string>> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const url = new URL(this.endpoint);
    url.searchParams.set("name", name);
    url.searchParams.set("type", String(DNS_TYPE[type]));
    logDebug(this.logger, "Resolving records over DoH", { name, type, resolver: this.name }, this.redaction);

    try {
      const response = await this.fetch(url.toString(), {
        headers: { accept: "application/dns-json" },
        signal: controller.signal,
      });

      if (!response.ok) {
        logWarn(
          this.logger,
          "DoH server returned an error",
          { name, type, resolver: this.name, status: response.status },
          this.redaction,
        );
        return createDetailedResult({
          name,
          type,
          resolver: this.name,
          status: "lookup-error",
          code: "RESOLVER_LOOKUP_ERROR",
          records: [],
          error: `DoH server returned HTTP ${response.status}.`,
        });
      }

      return parseDohJsonResponse(name, type, this.name, await response.json());
    } catch (error) {
      const message = getErrorMessage(error, "Unknown DoH lookup error.");
      logWarn(
        this.logger,
        "DoH lookup failed",
        { name, type, resolver: this.name, ...errorLogFields(error, "RESOLVER_LOOKUP_ERROR") },
        this.redaction,
      );

      return createDetailedResult({
        name,
        type,
        resolver: this.name,
        status: "lookup-error",
        code: "RESOLVER_LOOKUP_ERROR",
        records: [],
        error: `DoH lookup failed: ${message}`,
      });
    } finally {
      clearTimeout(timeout);
    }
  }
}

export class DotResolver implements TxtResolver, TlsaResolver {
  readonly name: string;
  readonly server: string;
  readonly port: number;
  private readonly logger: DiscoveryLogger | undefined;
  private readonly redaction: LoggerRedactionOptions | undefined;

  constructor(options: DotResolverOptions) {
    this.server = options.server;
    this.port = options.port ?? 853;
    this.name = options.name ?? `dot:${this.server}:${this.port}`;
    this.logger = options.logger;
    this.redaction = options.redaction;
  }

  async resolveTxt(name: string): Promise<string[]> {
    const result = await this.resolveTxtDetailed(name);
    return unwrapDetailedResult(result);
  }

  async resolveTxtDetailed(name: string): Promise<DetailedResolverResult<string>> {
    return this.createStubResult(normalizeDnsName(name), "TXT");
  }

  async resolveTlsa(hostname: string, port: number): Promise<ManifestTlsaRecord[]> {
    const result = await this.resolveTlsaDetailed(hostname, port);
    return unwrapDetailedResult(result);
  }

  async resolveTlsaDetailed(
    hostname: string,
    port: number,
  ): Promise<DetailedResolverResult<ManifestTlsaRecord>> {
    return this.createStubResult(createTlsaRecordName(hostname, port), "TLSA");
  }

  private createStubResult<TRecord>(
    name: string,
    type: ResolverRecordType,
  ): DetailedResolverResult<TRecord> {
    logWarn(
      this.logger,
      "DNS-over-TLS resolver is not implemented",
      { name, type, resolver: this.name },
      this.redaction,
    );
    return createDetailedResult({
      name,
      type,
      resolver: this.name,
      status: "lookup-error",
      code: "RESOLVER_UNSUPPORTED",
      records: [],
      error: "DNS-over-TLS resolver is a stub in this prototype.",
    });
  }
}

async function resolveFirstSuccess<TRecord>(
  name: string,
  type: ResolverRecordType,
  compositeName: string,
  resolvers: ResolverCandidate[],
  resolveAttempt: (
    resolver: ResolverCandidate,
    index: number,
  ) => Promise<DetailedResolverAttempt<TRecord>>,
  logger?: DiscoveryLogger,
  redaction?: LoggerRedactionOptions,
): Promise<DetailedResolverResult<TRecord>> {
  const attempts: DetailedResolverAttempt<TRecord>[] = [];

  for (const [index, resolver] of resolvers.entries()) {
    const attempt = await resolveAttempt(resolver, index);
    attempts.push(attempt);

    if (attempt.status === "ok") {
      return createDetailedResult({
        name,
        type,
        resolver: compositeName,
        records: attempt.records,
        attempts,
      });
    }
  }

  const noRecords = attempts.find((attempt) => attempt.status === "no-records");

  if (noRecords) {
    return createDetailedResult({
      name,
      type,
      resolver: compositeName,
      status: "no-records",
      records: [],
      attempts,
    });
  }

  logWarn(
    logger,
    "All resolvers failed",
    { name, type, resolver: compositeName },
    redaction,
  );

  return createDetailedResult({
    name,
    type,
    resolver: compositeName,
    status: "lookup-error",
    code: "RESOLVER_LOOKUP_ERROR",
    records: [],
    attempts,
    error: "All resolvers failed.",
  });
}

function resolveQuorum<TRecord>(
  name: string,
  type: ResolverRecordType,
  compositeName: string,
  attempts: DetailedResolverAttempt<TRecord>[],
  quorum: number,
  logger?: DiscoveryLogger,
  redaction?: LoggerRedactionOptions,
): DetailedResolverResult<TRecord> {
  const winner = findRecordSetWinner(attempts, quorum);

  if (winner) {
    return createDetailedResult({
      name,
      type,
      resolver: compositeName,
      status: winner.status,
      records: winner.records,
      attempts,
    });
  }

  logWarn(
    logger,
    "Resolver quorum failed",
    { name, type, resolver: compositeName, quorum },
    redaction,
  );

  return createDetailedResult({
    name,
    type,
    resolver: compositeName,
    status: "consensus-failed",
    code: "RESOLVER_CONSENSUS_FAILED",
    records: [],
    attempts,
    error: `No resolver answer reached quorum ${quorum}.`,
  });
}

function resolveStrictConsensus<TRecord>(
  name: string,
  type: ResolverRecordType,
  compositeName: string,
  attempts: DetailedResolverAttempt<TRecord>[],
  logger?: DiscoveryLogger,
  redaction?: LoggerRedactionOptions,
): DetailedResolverResult<TRecord> {
  if (attempts.some((attempt) => attempt.status === "lookup-error")) {
    logWarn(
      logger,
      "Strict resolver consensus failed on lookup error",
      { name, type, resolver: compositeName },
      redaction,
    );
    return createDetailedResult({
      name,
      type,
      resolver: compositeName,
      status: "lookup-error",
      code: "RESOLVER_LOOKUP_ERROR",
      records: [],
      attempts,
      error: "Strict consensus failed because at least one resolver returned a lookup error.",
    });
  }

  const winner = findRecordSetWinner(attempts, attempts.length);

  if (winner) {
    return createDetailedResult({
      name,
      type,
      resolver: compositeName,
      status: winner.status,
      records: winner.records,
      attempts,
    });
  }

  logWarn(
    logger,
    "Strict resolver consensus failed on mismatched answers",
    { name, type, resolver: compositeName },
    redaction,
  );

  return createDetailedResult({
    name,
    type,
    resolver: compositeName,
    status: "consensus-failed",
    code: "RESOLVER_CONSENSUS_FAILED",
    records: [],
    attempts,
    error: "Strict consensus failed because resolver answers differed.",
  });
}

function findRecordSetWinner<TRecord>(
  attempts: DetailedResolverAttempt<TRecord>[],
  threshold: number,
): { status: "ok" | "no-records"; records: TRecord[] } | undefined {
  const counts = new Map<string, { status: "ok" | "no-records"; records: TRecord[]; count: number }>();

  for (const attempt of attempts) {
    if (attempt.status === "lookup-error") {
      continue;
    }

    const status = attempt.status;
    const records = status === "no-records" ? [] : attempt.records;
    const key = `${status}:${createRecordSetKey(records)}`;
    const existing = counts.get(key);

    if (existing) {
      existing.count += 1;
      continue;
    }

    counts.set(key, { status, records, count: 1 });
  }

  return [...counts.values()].find((entry) => entry.count >= threshold);
}

async function resolveTxtAttempt(
  resolver: ResolverCandidate,
  name: string,
  index: number,
): Promise<DetailedResolverAttempt<string>> {
  const resolverName = getResolverName(resolver, index);

  try {
    const result = resolver.resolveTxtDetailed
      ? await resolver.resolveTxtDetailed(name)
      : createDetailedResult({
          name,
          type: "TXT",
          resolver: resolverName,
          records: await resolver.resolveTxt(name),
        });

    return toAttempt(result, resolverName);
  } catch (error) {
    return createAttemptError(resolverName, error);
  }
}

async function resolveTlsaAttempt(
  resolver: ResolverCandidate,
  hostname: string,
  port: number,
  index: number,
): Promise<DetailedResolverAttempt<ManifestTlsaRecord>> {
  const resolverName = getResolverName(resolver, index);
  if (!resolver.resolveTlsa && !resolver.resolveTlsaDetailed) {
    return createAttemptError(
      resolverName,
      discoveryError("RESOLVER_UNSUPPORTED", "Resolver does not support TLSA lookups."),
    );
  }

  try {
    let result: DetailedResolverResult<ManifestTlsaRecord>;

    if (resolver.resolveTlsaDetailed) {
      result = await resolver.resolveTlsaDetailed(hostname, port);
    } else if (resolver.resolveTlsa) {
      result = createDetailedResult({
        name: createTlsaRecordName(hostname, port),
        type: "TLSA",
        resolver: resolverName,
        records: await resolver.resolveTlsa(hostname, port),
      });
    } else {
      return createAttemptError(
        resolverName,
        discoveryError("RESOLVER_UNSUPPORTED", "Resolver does not support TLSA lookups."),
      );
    }

    return toAttempt(result, resolverName);
  } catch (error) {
    return createAttemptError(resolverName, error);
  }
}

function parseDohJsonResponse(
  name: string,
  type: ResolverRecordType,
  resolver: string,
  value: unknown,
): DetailedResolverResult<string> {
  if (!isRecord(value)) {
    return createDetailedResult({
      name,
      type,
      resolver,
      status: "lookup-error",
      code: "RESOLVER_LOOKUP_ERROR",
      records: [],
      error: "DoH response was not a JSON object.",
    });
  }

  const dnsStatus = typeof value.Status === "number" ? value.Status : undefined;

  if (dnsStatus === 3) {
    return createDetailedResult({ name, type, resolver, status: "no-records", records: [] });
  }

  if (dnsStatus !== 0) {
    return createDetailedResult({
      name,
      type,
      resolver,
      status: "lookup-error",
      code: "RESOLVER_LOOKUP_ERROR",
      records: [],
      error: `DoH response returned DNS status ${dnsStatus ?? "unknown"}.`,
    });
  }

  const answers = Array.isArray(value.Answer) ? (value.Answer as DohJsonAnswer[]) : [];
  const records = answers
    .filter((answer) => answer.type === DNS_TYPE[type] && typeof answer.data === "string")
    .map((answer) => answer.data as string);

  return createDetailedResult({ name, type, resolver, records });
}

function parseDohTxtAnswerData(data: string): string {
  const matches = [...data.matchAll(/"((?:\\.|[^"])*)"/g)];

  if (matches.length === 0) {
    return data.trim();
  }

  return matches.map((match) => unescapeDnsJsonString(match[1] ?? "")).join("");
}

function parseDohTlsaAnswerData(data: string): ManifestTlsaRecord {
  const [usage, selector, matchingType, ...associationParts] = data.trim().split(/\s+/);

  if (!usage || !selector || !matchingType || associationParts.length === 0) {
    throw new Error("DoH TLSA answer must contain usage, selector, matching type, and data.");
  }

  return {
    certUsage: Number(usage),
    selector: Number(selector),
    matchingType: Number(matchingType),
    data: associationParts.join(""),
  };
}

function unescapeDnsJsonString(value: string): string {
  return value
    .replace(/\\(\d{3})/g, (_match, code: string) => String.fromCharCode(Number(code)))
    .replace(/\\"/g, "\"")
    .replace(/\\\\/g, "\\");
}

function createDetailedResult<TRecord>(input: {
  name: string;
  type: ResolverRecordType;
  resolver: string;
  records: TRecord[];
  status?: ResolverStatus;
  code?: DiscoveryErrorCode;
  error?: string;
  attempts?: DetailedResolverAttempt<TRecord>[];
}): DetailedResolverResult<TRecord> {
  const status = input.status ?? (input.records.length > 0 ? "ok" : "no-records");

  return {
    name: input.name,
    type: input.type,
    status,
    records: input.records,
    resolver: input.resolver,
    ...(input.code ? { code: input.code } : {}),
    ...(input.error ? { error: input.error } : {}),
    ...(input.attempts ? { attempts: input.attempts } : {}),
  };
}

function createLookupErrorResult<TRecord>(
  name: string,
  type: ResolverRecordType,
  resolver: string,
  error: unknown,
): DetailedResolverResult<TRecord> {
  if (isNoRecordError(error)) {
    return createDetailedResult({ name, type, resolver, status: "no-records", records: [] });
  }

  const message = error instanceof Error ? error.message : "Unknown DNS error.";
  return createDetailedResult({
    name,
    type,
    resolver,
    status: "lookup-error",
    code: getErrorCode(error, "RESOLVER_LOOKUP_ERROR"),
    records: [],
    error: `${type} lookup failed for ${name}: ${message}`,
  });
}

function unwrapDetailedResult<TRecord>(result: DetailedResolverResult<TRecord>): TRecord[] {
  if (result.status === "ok" || result.status === "no-records") {
    return result.records;
  }

  throw discoveryError(
    result.code ?? "RESOLVER_LOOKUP_ERROR",
    result.error ?? `${result.type} lookup failed for ${result.name}.`,
    { name: result.name, type: result.type, resolver: result.resolver ?? "" },
  );
}

function toAttempt<TRecord>(
  result: DetailedResolverResult<TRecord>,
  fallbackResolver: string,
): DetailedResolverAttempt<TRecord> {
  return {
    resolver: result.resolver ?? fallbackResolver,
    status:
      result.status === "ok" || result.status === "no-records" ? result.status : "lookup-error",
    records: result.records,
    ...(result.code ? { code: result.code } : {}),
    ...(result.error ? { error: result.error } : {}),
  };
}

function createAttemptError<TRecord>(
  resolver: string,
  error: unknown,
): DetailedResolverAttempt<TRecord> {
  return {
    resolver,
    status: "lookup-error",
    records: [],
    code: getErrorCode(error, "RESOLVER_LOOKUP_ERROR"),
    error: getErrorMessage(error, "Unknown resolver error."),
  };
}

function createRecordSetKey<TRecord>(records: TRecord[]): string {
  return JSON.stringify(records.map(canonicalizeRecord).sort());
}

function canonicalizeRecord(value: unknown): string {
  return JSON.stringify(stableRecordValue(value));
}

function stableRecordValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableRecordValue);
  }

  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, stableRecordValue(item)]),
    );
  }

  return value;
}

function getResolverName(resolver: object, index: number): string {
  const candidate = "name" in resolver ? resolver.name : undefined;
  return typeof candidate === "string" && candidate.trim() ? candidate : `resolver-${index + 1}`;
}

function createTlsaRecordName(hostname: string, port: number): string {
  return `_${port}._tcp.${normalizeDnsName(hostname)}`;
}

function normalizeDnsName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, "");
}

function isNoRecordError(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code = "code" in error ? String(error.code) : "";
  return NO_RECORD_CODES.has(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
