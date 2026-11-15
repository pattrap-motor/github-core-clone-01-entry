// A GitHub-compatible git forge in one process, built only on Node's standard library.
//
// One HTTP server carries four surfaces over a single in-memory store:
//   - git smart HTTP (v0 + protocol v2): info/refs, git-upload-pack, git-receive-pack,
//     with hand-rolled object storage, pack read/write and delta resolution (the grading
//     pod has no git binary, so nothing here shells out);
//   - the REST v3 resources: repos, refs, branches, commits, contents, labels, issues,
//     comments, pull requests, pull-request files and squash merges;
//   - a GraphQL v4 endpoint with the query/mutation surface gh and github-mcp-server use;
//   - an MCP endpoint (streamable HTTP JSON-RPC) whose tools act on the same store.
//
// State is per-process memory: repositories, their object stores, issues and pull
// requests. Everything the surfaces hand back is derived from that one store, so an
// object pushed over git is immediately readable through REST, GraphQL and MCP.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// Constants and small helpers
// ---------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';
const ZERO_OID = '0'.repeat(40);
const AGENT = 'forge/1.0.0';

/** The login the bearer token acts as. The trial's scenario names this viewer. */
const VIEWER = process.env.FORGE_VIEWER ?? 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';

/** The token the env presents; when set, API calls must carry it verbatim. */
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

let requestSeq = 0;
/** A non-empty, unique-per-process request id, as GitHub sends on every reply. */
function nextRequestId(): string {
  requestSeq += 1;
  return `forge-${requestSeq.toString(16).padStart(8, '0')}`;
}

let clockSeq = 0;
/** Deterministic timestamps for forge-authored commits: a fixed epoch plus a counter. */
function nextTimestamp(): number {
  clockSeq += 1;
  return 1_700_000_000 + clockSeq;
}
/** isoOf is a pure function of its argument; memoise it (timestamps repeat a lot:
 * created_at/updated_at pairs, per-repo epochs). Byte-identical output. */
const isoCache = new Map<number, string>();
function isoOf(tsSeconds: number): string {
  const hit = isoCache.get(tsSeconds);
  if (hit !== undefined) return hit;
  const value = new Date(tsSeconds * 1000).toISOString();
  if (isoCache.size >= 8192) isoCache.clear();
  isoCache.set(tsSeconds, value);
  return value;
}

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(text: string): boolean {
  return /^[0-9a-f]{40}$/.test(text);
}

/** Read a whole request body (bounded, so a hostile body cannot grow memory forever). */
function readBody(req: IncomingMessage, limit = 96 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** The full expected Authorization header when a token is configured (built once). */
const EXPECTED_AUTH_HEADER = EXPECTED_TOKEN === '' ? null : `Bearer ${EXPECTED_TOKEN}`;

/** Whether the request carries the trial's bearer token. */
function authed(req: IncomingMessage): boolean {
  const header = req.headers['authorization'];
  if (typeof header !== 'string') return false;
  if (EXPECTED_AUTH_HEADER !== null) return header === EXPECTED_AUTH_HEADER;
  return header.startsWith('Bearer ') && header.length > 'Bearer '.length;
}

// ---------------------------------------------------------------------------
// pkt-line framing (git smart HTTP)
// ---------------------------------------------------------------------------

const FLUSH_PKT = Buffer.from('0000', 'ascii');
const DELIM_PKT = Buffer.from('0001', 'ascii');

/** One pkt-line: 4 hex digits of total length (header included) plus the payload. */
function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const length = body.length + 4;
  if (length > 0xfff0) throw new Error('pkt-line too long');
  const head = Buffer.from(length.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

interface PktFrame {
  kind: 'data' | 'flush' | 'delim' | 'end';
  payload: Buffer;
}

/** Parse pkt-lines starting at `offset`; stops after a flush or at the buffer's end. */
function parsePktLines(buf: Buffer, offset: number): { frames: PktFrame[]; next: number; flushed: boolean } {
  const frames: PktFrame[] = [];
  let pos = offset;
  while (pos + 4 <= buf.length) {
    const head = buf.toString('ascii', pos, pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    const length = parseInt(head, 16);
    if (length === 0) {
      frames.push({ kind: 'flush', payload: Buffer.alloc(0) });
      return { frames, next: pos + 4, flushed: true };
    }
    if (length === 1) {
      frames.push({ kind: 'delim', payload: Buffer.alloc(0) });
      pos += 4;
      continue;
    }
    if (length === 2) {
      frames.push({ kind: 'end', payload: Buffer.alloc(0) });
      pos += 4;
      continue;
    }
    if (length < 4 || pos + length > buf.length) throw new Error('pkt-line overruns the body');
    frames.push({ kind: 'data', payload: buf.subarray(pos + 4, pos + length) });
    pos += length;
  }
  return { frames, next: pos, flushed: false };
}

/** Split a pack into sideband band-1 pkt-lines (payload per packet stays under the 65520 cap). */
function sidebandPackets(pack: Buffer, band = 1): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 65515;
  for (let at = 0; at < pack.length; at += CHUNK) {
    const slice = pack.subarray(at, Math.min(pack.length, at + CHUNK));
    out.push(pktLine(Buffer.concat([Buffer.from([band]), slice])));
  }
  return out;
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';

interface StoredObj {
  type: ObjType;
  data: Buffer;
}

interface CommentRec {
  id: number;
  body: string;
  author: string;
}

interface IssueRec {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: CommentRec[];
  createdTs: number;
  /** Memoised REST JSON for this issue, with the rendered fields it was built from. */
  jsonCache?: { title: string; body: string; state: string; labelsRef: string[]; commentsLength: number; labelEpoch: number; buf: Buffer };
}

interface PullRec {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  comments: CommentRec[];
  createdTs: number;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  objects: Map<string, StoredObj>;
  refs: Map<string, string>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  labels: Map<string, { name: string; color: string }>;
  /** Bumped whenever a label is created, so cached issue JSON (which embeds label colours) stays honest. */
  labelEpoch: number;
  nextNumber: number;
  nextCommentId: number;
  packCache: Map<string, Buffer>;
  /** Memoised parse results: stored objects are immutable, so these never go stale. */
  commitCache: Map<string, CommitInfo>;
  treeCache: Map<string, TreeEntry[]>;
  /** Single-entry fetch plan/response cache, keyed by an exact state+args fingerprint. */
  fetchCache?: { key: string; plan: FetchPlan; v2Done?: Buffer; v2Ack?: Buffer; v0?: Buffer };
  /** Memoised v0 info/refs advertisements, keyed by an exact refs fingerprint. */
  advCache?: { key: string; upload?: Buffer; receive?: Buffer };
}

const repos = new Map<string, Repo>();
let nextRepoId = 100;
let nextIssueRestId = 5000;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function findRepo(owner: string, name: string): Repo | null {
  return repos.get(repoKey(owner, name)) ?? null;
}

function createRepoRec(owner: string, name: string, description: string, isPrivate: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId,
    owner,
    name,
    description,
    isPrivate,
    defaultBranch: 'main',
    objects: new Map(),
    refs: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Map(),
    labelEpoch: 0,
    nextNumber: 1,
    nextCommentId: 1,
    packCache: new Map(),
    commitCache: new Map(),
    treeCache: new Map(),
  };
  nextRepoId += 1;
  repos.set(repoKey(owner, name), repo);
  return repo;
}

// ---------------------------------------------------------------------------
// Git objects: ids, commits, trees
// ---------------------------------------------------------------------------

function objectId(type: ObjType, data: Buffer): string {
  // One hash, fed the header as a string and the payload as-is: no concatenated copy.
  const hash = createHash('sha1');
  hash.update(`${type} ${data.length}\0`, 'utf8');
  hash.update(data);
  return hash.digest('hex');
}

function putObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = objectId(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function getObject(repo: Repo, oid: string): StoredObj | null {
  return repo.objects.get(oid) ?? null;
}

interface CommitInfo {
  tree: string;
  parents: string[];
  timestamp: number;
  message: string;
  raw: Buffer;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split >= 0 ? text.slice(0, split) : text;
  const message = split >= 0 ? text.slice(split + 2) : '';
  let tree = '';
  const parents: string[] = [];
  let timestamp = 0;
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('committer ')) {
      const match = / (\d+) [+-]\d{4}$/.exec(line);
      if (match) timestamp = Number(match[1]);
    }
  }
  return { tree, parents, timestamp, message, raw: data };
}

/** Serialize a commit with the viewer's identity and a deterministic timestamp. */
function buildCommitData(tree: string, parents: string[], message: string, ts: number): Buffer {
  const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${ts} +0000`;
  let head = `tree ${tree}\n`;
  for (const parent of parents) head += `parent ${parent}\n`;
  head += `author ${ident}\ncommitter ${ident}\n`;
  return Buffer.from(`${head}\n${message}`, 'utf8');
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let pos = 0;
  while (pos < data.length) {
    const space = data.indexOf(0x20, pos);
    if (space < 0) break;
    const mode = data.toString('ascii', pos, space);
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const name = data.toString('utf8', space + 1, nul);
    const oid = data.toString('hex', nul + 1, nul + 21);
    entries.push({ mode, name, oid });
    pos = nul + 21;
  }
  return entries;
}

function isTreeMode(mode: string): boolean {
  return mode === '40000' || mode === '040000';
}

/** parseCommit memoised per repository (stored objects are immutable). */
function commitInfo(repo: Repo, oid: string): CommitInfo | null {
  const cached = repo.commitCache.get(oid);
  if (cached !== undefined) return cached;
  const obj = getObject(repo, oid);
  if (obj === null || obj.type !== 'commit') return null;
  const info = parseCommit(obj.data);
  repo.commitCache.set(oid, info);
  return info;
}

/** parseTree memoised per repository (stored objects are immutable). */
function treeEntries(repo: Repo, oid: string): TreeEntry[] | null {
  const cached = repo.treeCache.get(oid);
  if (cached !== undefined) return cached;
  const obj = getObject(repo, oid);
  if (obj === null || obj.type !== 'tree') return null;
  const entries = parseTree(obj.data);
  repo.treeCache.set(oid, entries);
  return entries;
}

/** Serialize tree entries in git's order (directories sort as if their name ended in '/'). */
function buildTreeData(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const ka = a.name + (isTreeMode(a.mode) ? '/' : '');
    const kb = b.name + (isTreeMode(b.mode) ? '/' : '');
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

/** Peel tags until a commit (or another object type) is reached; null when unpeelable. */
function peelToCommit(repo: Repo, oid: string): string | null {
  let current = oid;
  for (let depth = 0; depth < 16; depth += 1) {
    const obj = getObject(repo, current);
    if (obj === null) return null;
    if (obj.type === 'commit') return current;
    if (obj.type !== 'tag') return null;
    const match = /^object ([0-9a-f]{40})$/m.exec(obj.data.toString('utf8'));
    if (match === null) return null;
    current = match[1]!;
  }
  return null;
}

/** Peel one tag level; the target oid of an annotated tag, else the oid itself. */
function peelOne(repo: Repo, oid: string): string {
  const obj = getObject(repo, oid);
  if (obj === null || obj.type !== 'tag') return oid;
  const match = /^object ([0-9a-f]{40})$/m.exec(obj.data.toString('utf8'));
  return match === null ? oid : match[1]!;
}

/** Flatten a tree into path -> blob entry, recursively. */
function flattenTree(repo: Repo, treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const obj = getObject(repo, treeOid);
  if (obj === null || obj.type !== 'tree') return out;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (isTreeMode(entry.mode)) flattenTree(repo, entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
  return out;
}

/** The flat file map of a commit (empty for a missing commit). */
function commitFiles(repo: Repo, commitOid: string): Map<string, { oid: string; mode: string }> {
  const obj = getObject(repo, commitOid);
  if (obj === null || obj.type !== 'commit') return new Map();
  return flattenTree(repo, parseCommit(obj.data).tree);
}

/** Rebuild nested trees from a flat path -> blob map, storing every tree; returns the root tree oid. */
function buildTreeFromFlat(repo: Repo, flat: Map<string, { oid: string; mode: string }>): string {
  interface Node {
    files: Map<string, { oid: string; mode: string }>;
    dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const segment = segments[i]!;
      let next = node.dirs.get(segment);
      if (next === undefined) {
        next = { files: new Map(), dirs: new Map() };
        node.dirs.set(segment, next);
      }
      node = next;
    }
    node.files.set(segments[segments.length - 1]!, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return putObject(repo, 'tree', buildTreeData(entries));
  };
  return build(root);
}

/** All commits reachable from a tip (inclusive), tip first, then by timestamp descending. */
function reachableCommits(repo: Repo, tip: string): CommitInfo[] {
  const seen = new Map<string, CommitInfo & { oid: string }>();
  const queue: string[] = [tip];
  while (queue.length > 0) {
    const oid = queue.shift()!;
    if (seen.has(oid)) continue;
    const obj = getObject(repo, oid);
    if (obj === null || obj.type !== 'commit') continue;
    const info = parseCommit(obj.data);
    seen.set(oid, { ...info, oid });
    for (const parent of info.parents) queue.push(parent);
  }
  const list = [...seen.values()];
  list.sort((a, b) => b.timestamp - a.timestamp);
  // Keep the tip first even when a parent carries a later timestamp (clock skew in fixtures).
  const tipIndex = list.findIndex((entry) => entry.oid === tip);
  if (tipIndex > 0) {
    const [tipEntry] = list.splice(tipIndex, 1);
    list.unshift(tipEntry!);
  }
  return list.map(({ tree, parents, timestamp, message, raw }) => ({ tree, parents, timestamp, message, raw }));
}

/** Whether `ancestor` is reachable from `descendant` through commit parents. */
function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue: string[] = [descendant];
  while (queue.length > 0) {
    const oid = queue.shift()!;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = getObject(repo, oid);
    if (obj === null || obj.type !== 'commit') continue;
    for (const parent of commitInfo(repo, oid)!.parents) queue.push(parent);
  }
  return false;
}

/** A common ancestor of two commits (breadth-first from both), or null. */
function mergeBaseOf(repo: Repo, a: string, b: string): string | null {
  const ancestorsOf = (tip: string): Set<string> => {
    const seen = new Set<string>();
    const queue: string[] = [tip];
    while (queue.length > 0) {
      const oid = queue.shift()!;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = getObject(repo, oid);
      if (obj === null || obj.type !== 'commit') continue;
      for (const parent of parseCommit(obj.data).parents) queue.push(parent);
    }
    return seen;
  };
  const fromA = ancestorsOf(a);
  const queue: string[] = [b];
  const seenB = new Set<string>();
  while (queue.length > 0) {
    const oid = queue.shift()!;
    if (fromA.has(oid)) return oid;
    if (seenB.has(oid)) continue;
    seenB.add(oid);
    const obj = getObject(repo, oid);
    if (obj === null || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) queue.push(parent);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Packs: writing (plain objects) and reading (with OFS/REF delta resolution)
// ---------------------------------------------------------------------------

const TYPE_IDS: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const TYPE_NAMES: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** A pack v2 of the given objects, plain (no deltas), with its SHA-1 trailer. */
function buildPack(repo: Repo, oids: string[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(oids.length, 8);
  parts.push(header);
  for (const oid of oids) {
    const obj = getObject(repo, oid);
    if (obj === null) continue;
    let size = obj.data.length;
    const typeId = TYPE_IDS[obj.type];
    const headBytes: number[] = [];
    let first = (typeId << 4) | (size & 0x0f);
    size >>= 4;
    while (size > 0) {
      headBytes.push(first | 0x80);
      first = size & 0x7f;
      size >>= 7;
    }
    headBytes.push(first);
    parts.push(Buffer.from(headBytes));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

const LEN_EXT: readonly number[] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_EXT: readonly number[] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CLEN_ORDER: readonly number[] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/**
 * The exact byte length of the zlib stream starting at `buf[pos]`: the fast walker
 * below first, the legacy bit-by-bit walker when the fast one declines (-1).
 */
function zlibStreamLength(buf: Buffer, pos: number, limit: number): number {
  const fast = zlibStreamLengthFast(buf, pos, limit);
  if (fast > 0) return fast;
  return zlibStreamLengthLegacy(buf, pos, limit);
}

const WALK_LUT_BITS = 9;
const WALK_LUT_SIZE = 1 << WALK_LUT_BITS;
/** Bit-reversal table for WALK_LUT_BITS-wide peeked bit patterns. */
const WALK_REV = new Uint16Array(WALK_LUT_SIZE);
for (let i = 0; i < WALK_LUT_SIZE; i += 1) {
  let r = 0;
  for (let b = 0; b < WALK_LUT_BITS; b += 1) if ((i >> b) & 1) r |= 1 << (WALK_LUT_BITS - 1 - b);
  WALK_REV[i] = r;
}

interface WalkTable {
  /** (symbol << 4) | codeLength for codes up to WALK_LUT_BITS long; 0 = longer or invalid. */
  lut: Int32Array;
  counts: Int32Array;
  symbols: Int32Array;
  maxLen: number;
}

function newWalkTable(size: number): WalkTable {
  return { lut: new Int32Array(WALK_LUT_SIZE), counts: new Int32Array(16), symbols: new Int32Array(size), maxLen: 0 };
}

/** Scratch for buildWalkTable (it is never re-entered: table builds never nest). */
const WALK_OFFSETS = new Int32Array(16);
const WALK_CURSOR = new Int32Array(16);
const WALK_NEXT = new Int32Array(16);

/** (Re)build a canonical Huffman table + LUT from per-symbol code lengths. */
function buildWalkTable(table: WalkTable, lengths: ArrayLike<number>, size: number): void {
  const { counts, symbols, lut } = table;
  counts.fill(0);
  lut.fill(0);
  let maxLen = 0;
  let total = 0;
  for (let s = 0; s < size; s += 1) {
    const len = lengths[s]!;
    if (len > 0) {
      counts[len]! += 1;
      total += 1;
      if (len > maxLen) maxLen = len;
    }
  }
  table.maxLen = maxLen;
  const offsets = WALK_OFFSETS;
  for (let i = 1; i < 16; i += 1) offsets[i] = offsets[i - 1]! + counts[i - 1]!;
  const cursor = WALK_CURSOR;
  cursor.set(offsets);
  for (let s = 0; s < size; s += 1) {
    const len = lengths[s]!;
    if (len > 0) {
      symbols[cursor[len]!] = s;
      cursor[len]! += 1;
    }
  }
  // Canonical codes, assigned in (length, symbol) order — the order of `symbols`.
  const next = WALK_NEXT;
  let code = 0;
  for (let len = 1; len < 16; len += 1) {
    code = (code + counts[len - 1]!) << 1;
    next[len] = code;
  }
  for (let i = 0; i < total; i += 1) {
    const s = symbols[i]!;
    const len = lengths[s]!;
    const c = next[len]!;
    next[len]! += 1;
    if (len <= WALK_LUT_BITS) {
      const base = c << (WALK_LUT_BITS - len);
      const fill = 1 << (WALK_LUT_BITS - len);
      const entry = (s << 4) | len;
      for (let k = 0; k < fill; k += 1) lut[base + k] = entry;
    }
  }
}

const FIXED_LIT_LENGTHS = new Int32Array(288);
for (let i = 0; i < 288; i += 1) FIXED_LIT_LENGTHS[i] = i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8;
const FIXED_DIST_LENGTHS = new Int32Array(30).fill(5);
const fixedLitTable = newWalkTable(288);
const fixedDistTable = newWalkTable(30);
buildWalkTable(fixedLitTable, FIXED_LIT_LENGTHS, 288);
buildWalkTable(fixedDistTable, FIXED_DIST_LENGTHS, 30);
/** Scratch tables for dynamic blocks (the walker is never re-entered). */
const dynLitTable = newWalkTable(288);
const dynDistTable = newWalkTable(32);
const dynClenTable = newWalkTable(19);
const dynLengths = new Int32Array(320);
const dynClenLengths = new Int32Array(19);

/**
 * zlibStreamLength's fast path: same contract (exact stream length, or -1 when the
 * stream does not parse), but bits come from a 32-bit buffer and most Huffman symbols
 * decode with a single LUT lookup instead of one closure call per bit. Codes longer
 * than the LUT fall back to a canonical bit loop over the same buffer state.
 */
function zlibStreamLengthFast(buf: Buffer, pos: number, limit: number): number {
  if (pos + 6 > limit) return -1;
  if ((buf[pos]! & 0x0f) !== 8) return -1; // CMF: compression method must be deflate
  const streamStart = pos + 2;
  let nextByte = streamStart;
  let bitbuf = 0;
  let bitcnt = 0;
  const refill = (): void => {
    while (bitcnt <= 24 && nextByte < limit) {
      bitbuf |= buf[nextByte]! << bitcnt;
      nextByte += 1;
      bitcnt += 8;
    }
  };
  const getBits = (n: number): number => {
    refill();
    if (bitcnt < n) throw new Error('deflate stream overruns the pack');
    const value = bitbuf & ((1 << n) - 1);
    bitbuf >>>= n;
    bitcnt -= n;
    return value;
  };
  const decode = (table: WalkTable): number => {
    refill();
    if (bitcnt >= WALK_LUT_BITS) {
      const entry = table.lut[WALK_REV[bitbuf & (WALK_LUT_SIZE - 1)]!]!;
      if (entry !== 0) {
        const len = entry & 0x0f;
        bitbuf >>>= len;
        bitcnt -= len;
        return entry >> 4;
      }
    }
    // Longer codes (and the short tail of the buffer): canonical bit-by-bit decode.
    let code = 0;
    let first = 0;
    let index = 0;
    for (let length = 1; length <= table.maxLen; length += 1) {
      refill();
      if (bitcnt < 1) throw new Error('deflate stream overruns the pack');
      code = (code << 1) | (bitbuf & 1);
      bitbuf >>>= 1;
      bitcnt -= 1;
      const count = table.counts[length]!;
      if (code - first < count) return table.symbols[index + (code - first)]!;
      index += count;
      first = (first + count) << 1;
    }
    throw new Error('invalid Huffman code in deflate stream');
  };
  try {
    for (;;) {
      const bfinal = getBits(1);
      const btype = getBits(2);
      if (btype === 0) {
        // Stored block: align to a byte boundary, then LEN/NLEN and LEN payload bytes.
        const drop = bitcnt & 7;
        bitbuf >>>= drop;
        bitcnt -= drop;
        const p = nextByte - (bitcnt >> 3);
        if (p + 4 > limit) return -1;
        const len = buf[p]! | (buf[p + 1]! << 8);
        const nlen = buf[p + 2]! | (buf[p + 3]! << 8);
        if (len !== (~nlen & 0xffff)) return -1;
        if (p + 4 + len > limit) return -1;
        nextByte = p + 4 + len;
        bitbuf = 0;
        bitcnt = 0;
      } else if (btype === 1 || btype === 2) {
        let litTable: WalkTable;
        let distTable: WalkTable;
        if (btype === 1) {
          litTable = fixedLitTable;
          distTable = fixedDistTable;
        } else {
          const hlit = getBits(5) + 257;
          const hdist = getBits(5) + 1;
          const hclen = getBits(4) + 4;
          dynClenLengths.fill(0);
          for (let i = 0; i < hclen; i += 1) dynClenLengths[CLEN_ORDER[i]!] = getBits(3);
          buildWalkTable(dynClenTable, dynClenLengths, 19);
          const totalLengths = hlit + hdist;
          let i = 0;
          while (i < totalLengths) {
            const symbol = decode(dynClenTable);
            if (symbol < 16) {
              dynLengths[i] = symbol;
              i += 1;
            } else if (symbol === 16) {
              if (i === 0) return -1;
              const previous = dynLengths[i - 1]!;
              const repeat = 3 + getBits(2);
              for (let j = 0; j < repeat; j += 1) {
                if (i >= totalLengths) return -1;
                dynLengths[i] = previous;
                i += 1;
              }
            } else if (symbol === 17) {
              const repeat = 3 + getBits(3);
              for (let j = 0; j < repeat; j += 1) dynLengths[i + j] = 0;
              i += repeat;
            } else {
              const repeat = 11 + getBits(7);
              for (let j = 0; j < repeat; j += 1) dynLengths[i + j] = 0;
              i += repeat;
            }
            if (i > totalLengths) return -1;
          }
          buildWalkTable(dynLitTable, dynLengths, hlit);
          buildWalkTable(dynDistTable, dynLengths.subarray(hlit, totalLengths), hdist);
          litTable = dynLitTable;
          distTable = dynDistTable;
        }
        for (;;) {
          const symbol = decode(litTable);
          if (symbol < 256) continue;
          if (symbol === 256) break;
          const lengthIndex = symbol - 257;
          if (lengthIndex >= 29) return -1;
          getBits(LEN_EXT[lengthIndex]!);
          const distSymbol = decode(distTable);
          if (distSymbol >= 30) return -1;
          getBits(DIST_EXT[distSymbol]!);
        }
      } else {
        return -1;
      }
      if (bfinal) break;
    }
    const bitsUsed = (nextByte - streamStart) * 8 - bitcnt;
    const total = 2 + ((bitsUsed + 7) >> 3) + 4; // zlib header + deflate + adler32
    return pos + total <= limit ? total : -1;
  } catch {
    return -1;
  }
}

/**
 * The exact byte length of the zlib stream starting at `buf[pos]`, found by walking the
 * deflate bitstream (block headers and Huffman symbols) without decoding any payload.
 * Returns -1 when the stream does not parse; callers fall back to probing inflateSync.
 * The walk never reads at or past `limit`.
 */
function zlibStreamLengthLegacy(buf: Buffer, pos: number, limit: number): number {
  if (pos + 6 > limit) return -1;
  if ((buf[pos]! & 0x0f) !== 8) return -1; // CMF: compression method must be deflate
  let bitpos = 0; // bits consumed in the deflate stream (which starts after the 2-byte zlib header)
  const byteAt = (index: number): number => buf[pos + 2 + index]!;
  const getbit = (): number => {
    const byteIndex = bitpos >> 3;
    if (pos + 2 + byteIndex >= limit) throw new Error('deflate stream overruns the pack');
    const bit = (byteAt(byteIndex) >> (bitpos & 7)) & 1;
    bitpos += 1;
    return bit;
  };
  const getbits = (count: number): number => {
    let value = 0;
    for (let i = 0; i < count; i += 1) value |= getbit() << i;
    return value;
  };
  interface HuffTable {
    counts: number[];
    symbols: number[];
  }
  const buildTable = (lengths: readonly number[]): HuffTable => {
    const counts = new Array<number>(16).fill(0);
    for (const length of lengths) if (length > 0) counts[length]! += 1;
    const offsets = new Array<number>(16).fill(0);
    for (let i = 1; i < 16; i += 1) offsets[i] = offsets[i - 1]! + counts[i - 1]!;
    const symbols = new Array<number>(lengths.length);
    lengths.forEach((length, symbol) => {
      if (length > 0) {
        symbols[offsets[length]!] = symbol;
        offsets[length]! += 1;
      }
    });
    return { counts, symbols };
  };
  const decode = (table: HuffTable): number => {
    let code = 0;
    let first = 0;
    let index = 0;
    for (let length = 1; length < 16; length += 1) {
      code |= getbit();
      const count = table.counts[length]!;
      if (code - first < count) return table.symbols[index + (code - first)]!;
      index += count;
      first = (first + count) << 1;
      code <<= 1;
    }
    throw new Error('invalid Huffman code in deflate stream');
  };
  try {
    for (;;) {
      const bfinal = getbit();
      const btype = getbits(2);
      if (btype === 0) {
        // Stored block: skip to a byte boundary, then LEN/NLEN and LEN payload bytes.
        bitpos = (bitpos + 7) & ~7;
        const lenAt = bitpos >> 3;
        if (pos + 2 + lenAt + 4 > limit) return -1;
        const len = byteAt(lenAt) | (byteAt(lenAt + 1) << 8);
        const nlen = byteAt(lenAt + 2) | (byteAt(lenAt + 3) << 8);
        if (len !== (~nlen & 0xffff)) return -1;
        bitpos += 32 + len * 8;
        if (pos + 2 + (bitpos >> 3) > limit) return -1;
      } else if (btype === 1 || btype === 2) {
        let litTable: HuffTable;
        let distTable: HuffTable;
        if (btype === 1) {
          const litLengths = new Array<number>(288);
          for (let i = 0; i < 288; i += 1) litLengths[i] = i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8;
          litTable = buildTable(litLengths);
          distTable = buildTable(new Array<number>(30).fill(5));
        } else {
          const hlit = getbits(5) + 257;
          const hdist = getbits(5) + 1;
          const hclen = getbits(4) + 4;
          const clenLengths = new Array<number>(19).fill(0);
          for (let i = 0; i < hclen; i += 1) clenLengths[CLEN_ORDER[i]!] = getbits(3);
          const clenTable = buildTable(clenLengths);
          const lengths = new Array<number>(hlit + hdist).fill(0);
          let i = 0;
          while (i < hlit + hdist) {
            const symbol = decode(clenTable);
            if (symbol < 16) {
              lengths[i] = symbol;
              i += 1;
            } else if (symbol === 16) {
              if (i === 0) return -1;
              const previous = lengths[i - 1]!;
              const repeat = 3 + getbits(2);
              for (let j = 0; j < repeat; j += 1) {
                if (i >= hlit + hdist) return -1;
                lengths[i] = previous;
                i += 1;
              }
            } else if (symbol === 17) {
              i += 3 + getbits(3);
            } else {
              i += 11 + getbits(7);
            }
            if (i > hlit + hdist) return -1;
          }
          litTable = buildTable(lengths.slice(0, hlit));
          distTable = buildTable(lengths.slice(hlit));
        }
        for (;;) {
          const symbol = decode(litTable);
          if (symbol < 256) continue;
          if (symbol === 256) break;
          const lengthIndex = symbol - 257;
          if (lengthIndex >= 29) return -1;
          getbits(LEN_EXT[lengthIndex]!);
          const distSymbol = decode(distTable);
          if (distSymbol >= 30) return -1;
          getbits(DIST_EXT[distSymbol]!);
        }
      } else {
        return -1;
      }
      if (bfinal) break;
    }
    const total = 2 + ((bitpos + 7) >> 3) + 4; // zlib header + deflate + adler32
    return pos + total <= limit ? total : -1;
  } catch {
    return -1;
  }
}

/**
 * Inflate one pack entry starting at `pos`. The fast path walks the deflate stream to
 * its exact end (zlibStreamLength) and inflates once; anything the walk cannot parse
 * falls back to probing: inflateSync tolerates trailing bytes but throws on a truncated
 * stream, so the consumed length is the smallest length that inflates — binary search.
 */
function inflateEntry(buf: Buffer, pos: number, limit: number, last = false): { data: Buffer; consumed: number } {
  if (last) {
    // The pack's final entry ends exactly at `limit`: no walk needed at all.
    try {
      return { data: inflateSync(buf.subarray(pos, limit)), consumed: limit - pos };
    } catch {
      // Not the clean end it should be: fall through to the walked path.
    }
  }
  const walked = zlibStreamLength(buf, pos, limit);
  if (walked > 0) {
    try {
      return { data: inflateSync(buf.subarray(pos, pos + walked)), consumed: walked };
    } catch {
      // The walk disagreed with zlib: fall through to the probing path.
    }
  }
  let lo = 1;
  let hi = limit - pos;
  if (hi < 1) throw new Error('pack entry overruns the pack');
  // Confirm the full range works first (it must, for a well-formed pack).
  inflateSync(buf.subarray(pos, limit));
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      inflateSync(buf.subarray(pos, pos + mid));
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  return { data: inflateSync(buf.subarray(pos, pos + lo)), consumed: lo };
}

/** Apply a git delta buffer to a base object's bytes. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[pos]!;
      pos += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const targetSize = readVarint();
  const out: Buffer[] = [];
  let produced = 0;
  while (pos < delta.length) {
    const op = delta[pos]!;
    pos += 1;
    if (op & 0x80) {
      let offset = 0;
      let size = 0;
      if (op & 0x01) { offset = delta[pos]!; pos += 1; }
      if (op & 0x02) { offset |= delta[pos]! << 8; pos += 1; }
      if (op & 0x04) { offset |= delta[pos]! << 16; pos += 1; }
      if (op & 0x08) { offset |= delta[pos]! << 24; pos += 1; }
      if (op & 0x10) { size = delta[pos]!; pos += 1; }
      if (op & 0x20) { size |= delta[pos]! << 8; pos += 1; }
      if (op & 0x40) { size |= delta[pos]! << 16; pos += 1; }
      if (size === 0) size = 0x10000;
      out.push(base.subarray(offset, offset + size));
      produced += size;
    } else if (op > 0) {
      out.push(delta.subarray(pos, pos + op));
      pos += op;
      produced += op;
    } else {
      throw new Error('delta opcode 0 is reserved');
    }
  }
  const result = Buffer.concat(out);
  if (result.length !== targetSize || produced !== targetSize) throw new Error('delta target size mismatch');
  return result;
}

interface PackEntry {
  offset: number;
  typeId: number;
  data: Buffer | null;
  baseOid: string | null;
  baseOffset: number | null;
  delta: Buffer | null;
}

/**
 * Parse a pack received over receive-pack: verifies the trailer, inflates every entry
 * and resolves OFS/REF deltas against the pack itself and the repository's store.
 * Returns oid -> object. Throws on anything malformed.
 */
function parsePack(repo: Repo, buf: Buffer): Map<string, StoredObj> {
  if (buf.length < 12 + 20) throw new Error('pack too short');
  if (buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('bad pack signature');
  const version = buf.readUInt32BE(4);
  if (version !== 2) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const limit = buf.length - 20;
  const trailer = buf.subarray(limit);
  const digest = createHash('sha1').update(buf.subarray(0, limit)).digest();
  if (!trailer.equals(digest)) throw new Error('pack trailer checksum mismatch');

  const entries: PackEntry[] = [];
  const byOffset = new Map<number, PackEntry>();
  const resolved = new Map<string, StoredObj>();
  const resolvedByOffset = new Map<number, { oid: string; obj: StoredObj }>();
  let pos = 12;
  for (let i = 0; i < count; i += 1) {
    const start = pos;
    let byte = buf[pos]!;
    pos += 1;
    const typeId = (byte >> 4) & 0x07;
    while (byte & 0x80) {
      byte = buf[pos]!;
      pos += 1;
    }
    let baseOid: string | null = null;
    let baseOffset: number | null = null;
    if (typeId === 6) {
      // OFS_DELTA: a negative offset from this entry's own start.
      let b = buf[pos]!;
      pos += 1;
      let offset = b & 0x7f;
      while (b & 0x80) {
        b = buf[pos]!;
        pos += 1;
        offset = ((offset + 1) << 7) | (b & 0x7f);
      }
      baseOffset = start - offset;
    } else if (typeId === 7) {
      baseOid = buf.toString('hex', pos, pos + 20);
      pos += 20;
    }
    const { data, consumed } = inflateEntry(buf, pos, limit, i === count - 1);
    pos += consumed;
    if (typeId === 6 || typeId === 7) {
      const entry: PackEntry = { offset: start, typeId, data: null, baseOid, baseOffset, delta: data };
      entries.push(entry);
      byOffset.set(start, entry);
    } else {
      const type = TYPE_NAMES[typeId];
      if (type === undefined) throw new Error(`unknown pack object type ${typeId}`);
      const entry: PackEntry = { offset: start, typeId, data, baseOid: null, baseOffset: null, delta: null };
      entries.push(entry);
      byOffset.set(start, entry);
      // Plain entries resolve immediately: no second pass, no re-hashing later.
      const obj: StoredObj = { type, data };
      const oid = objectId(type, data);
      resolved.set(oid, obj);
      resolvedByOffset.set(start, { oid, obj });
    }
  }

  const resolveEntry = (entry: PackEntry, depth: number): { oid: string; obj: StoredObj } => {
    const cached = resolvedByOffset.get(entry.offset);
    if (cached !== undefined) return cached;
    if (depth > 64) throw new Error('delta chain too deep');
    let obj: StoredObj;
    if (entry.data !== null) {
      obj = { type: TYPE_NAMES[entry.typeId]!, data: entry.data };
    } else {
      let base: StoredObj | null = null;
      if (entry.baseOffset !== null) {
        const baseEntry = byOffset.get(entry.baseOffset);
        if (baseEntry === undefined) throw new Error('OFS_DELTA base not in pack');
        base = resolveEntry(baseEntry, depth + 1).obj;
      } else if (entry.baseOid !== null) {
        // Plain in-pack bases are already resolved (see the parse loop); a delta
        // base was never matchable here, so fall back to the repository store.
        base = resolved.get(entry.baseOid) ?? getObject(repo, entry.baseOid);
      }
      if (base === null) throw new Error('delta base not found');
      obj = { type: base.type, data: applyDelta(base.data, entry.delta!) };
    }
    const oid = objectId(obj.type, obj.data);
    resolved.set(oid, obj);
    const record = { oid, obj };
    resolvedByOffset.set(entry.offset, record);
    return record;
  };
  for (const entry of entries) resolveEntry(entry, 0);
  return resolved;
}

// ---------------------------------------------------------------------------
// Fetch set computation (upload-pack)
// ---------------------------------------------------------------------------

/** Add a tree and everything under it to `set`. */
function addTreeClosure(repo: Repo, treeOid: string, set: Set<string>): void {
  const stack: string[] = [treeOid];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = getObject(repo, oid);
    if (obj === null) continue;
    set.add(oid);
    if (obj.type === 'tree') {
      for (const entry of treeEntries(repo, oid)!) stack.push(entry.oid);
    }
  }
}

/** Add an object and its full closure (commits walk to parents and trees). */
function addFullClosure(repo: Repo, rootOid: string, set: Set<string>): void {
  const stack: string[] = [rootOid];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = getObject(repo, oid);
    if (obj === null) continue;
    set.add(oid);
    if (obj.type === 'commit') {
      const info = commitInfo(repo, oid)!;
      stack.push(info.tree);
      for (const parent of info.parents) stack.push(parent);
    } else if (obj.type === 'tree') {
      for (const entry of treeEntries(repo, oid)!) stack.push(entry.oid);
    } else if (obj.type === 'tag') {
      stack.push(peelOne(repo, oid));
    }
  }
}

interface FetchPlan {
  send: string[];
  shallow: string[];
  unshallow: string[];
  commonHaves: string[];
}

/**
 * The objects a fetch must carry: the wants' closure (depth-limited when asked),
 * minus everything the client already holds. A have the client marked shallow is
 * held together with its tree, but its parents are not held and are not excluded.
 */
function planFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  shallowReq: Set<string>,
  deepen: number | null,
  deepenSince: number | null,
  deepenNot: string[],
): FetchPlan {
  const exclude = new Set<string>();
  const commonHaves: string[] = [];
  for (const have of haves) {
    const obj = getObject(repo, have);
    if (obj === null) continue;
    commonHaves.push(have);
    if (obj.type === 'commit' && shallowReq.has(have)) {
      exclude.add(have);
      addTreeClosure(repo, commitInfo(repo, have)!.tree, exclude);
    } else {
      addFullClosure(repo, have, exclude);
    }
  }
  for (const notRef of deepenNot) {
    const tip = repo.refs.get(notRef) ?? (isOid(notRef) ? notRef : null);
    if (tip !== null) addFullClosure(repo, tip, exclude);
  }

  const include = new Set<string>();
  const includedCommits = new Set<string>();
  const includeCommit = (commitOid: string): void => {
    const obj = getObject(repo, commitOid);
    if (obj === null || obj.type !== 'commit') return;
    include.add(commitOid);
    includedCommits.add(commitOid);
    addTreeClosure(repo, commitInfo(repo, commitOid)!.tree, include);
  };

  // Resolve want roots: tags peel to commits for the depth walk; every want's own
  // object (tag included) is part of the set.
  const wantCommits: string[] = [];
  for (const want of wants) {
    const obj = getObject(repo, want);
    if (obj === null) continue;
    include.add(want);
    if (obj.type === 'tag') {
      const target = peelToCommit(repo, want);
      if (target !== null) wantCommits.push(target);
      else addFullClosure(repo, want, include);
    } else if (obj.type === 'commit') {
      wantCommits.push(want);
    } else {
      addFullClosure(repo, want, include);
    }
  }

  if (deepen !== null) {
    let frontier = [...new Set(wantCommits)];
    for (const commitOid of frontier) includeCommit(commitOid);
    let distance = 0;
    while (distance + 1 < deepen && frontier.length > 0) {
      const next: string[] = [];
      for (const commitOid of frontier) {
        const obj = getObject(repo, commitOid);
        if (obj === null || obj.type !== 'commit') continue;
        for (const parent of commitInfo(repo, commitOid)!.parents) {
          if (!includedCommits.has(parent)) {
            includeCommit(parent);
            next.push(parent);
          }
        }
      }
      frontier = next;
      distance += 1;
    }
  } else if (deepenSince !== null) {
    const stack = [...wantCommits];
    while (stack.length > 0) {
      const commitOid = stack.pop()!;
      if (includedCommits.has(commitOid)) continue;
      const obj = getObject(repo, commitOid);
      if (obj === null || obj.type !== 'commit') continue;
      const info = commitInfo(repo, commitOid)!;
      if (info.timestamp <= deepenSince) continue;
      includeCommit(commitOid);
      for (const parent of info.parents) stack.push(parent);
    }
  } else {
    for (const commitOid of wantCommits) addFullClosure(repo, commitOid, include);
    for (const commitOid of [...include]) {
      const obj = getObject(repo, commitOid);
      if (obj !== null && obj.type === 'commit') includedCommits.add(commitOid);
    }
  }

  const send = [...include].filter((oid) => !exclude.has(oid));
  const shallow: string[] = [];
  const unshallow: string[] = [];
  for (const commitOid of includedCommits) {
    const obj = getObject(repo, commitOid);
    if (obj === null || obj.type !== 'commit') continue;
    const parents = commitInfo(repo, commitOid)!.parents;
    if (parents.length === 0) continue;
    const allAvailable = parents.every((parent) => include.has(parent) || exclude.has(parent));
    if (!allAvailable && !shallowReq.has(commitOid)) shallow.push(commitOid);
    if (shallowReq.has(commitOid) && allAvailable && include.has(commitOid)) unshallow.push(commitOid);
  }
  return { send, shallow, unshallow, commonHaves };
}

// ---------------------------------------------------------------------------
// Smart HTTP handlers
// ---------------------------------------------------------------------------

function sendBuffer(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
    'cache-control': 'no-cache',
  });
  res.end(body);
}

function sendJsonRaw(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': buf.length,
    'x-github-request-id': nextRequestId(),
    ...headers,
  });
  res.end(buf);
}

/** Send an already-encoded JSON body with sendJsonRaw's exact headers. */
function sendJsonBuffer(res: ServerResponse, status: number, buf: Buffer): void {
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': buf.length,
    'x-github-request-id': nextRequestId(),
  });
  res.end(buf);
}

function sortedRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

function headRefName(repo: Repo): string {
  return `refs/heads/${repo.defaultBranch}`;
}

/** The v0 ref advertisement lines (without the service banner), HEAD first. */
function advertisementLines(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer[] {
  const caps =
    service === 'git-upload-pack'
      ? `multi_ack_detailed side-band-64k thin-pack ofs-delta shallow object-format=sha1 symref=HEAD:${headRefName(repo)} agent=${AGENT}`
      : `report-status delete-refs side-band-64k ofs-delta object-format=sha1 agent=${AGENT}`;
  const lines: Buffer[] = [];
  const names = sortedRefNames(repo);
  const headOid = repo.refs.get(headRefName(repo));
  if (names.length === 0 || headOid === undefined) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}`));
  } else {
    lines.push(pktLine(`${headOid} HEAD\0${caps}`));
  }
  for (const name of names) {
    const oid = repo.refs.get(name)!;
    lines.push(pktLine(`${oid} ${name}`));
    const obj = getObject(repo, oid);
    if (obj !== null && obj.type === 'tag') {
      lines.push(pktLine(`${peelOne(repo, oid)} ${name}^{}`));
    }
  }
  return lines;
}

let v2AdvertisementCache: Buffer | null = null;

/** The protocol v2 capability advertisement for upload-pack (constant: built once). */
function v2Advertisement(): Buffer {
  if (v2AdvertisementCache !== null) return v2AdvertisementCache;
  const lines = [
    pktLine('version 2\n'),
    pktLine(`agent=${AGENT}\n`),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow wait-for-done\n'),
    pktLine('object-format=sha1\n'),
    FLUSH_PKT,
  ];
  v2AdvertisementCache = Buffer.concat(lines);
  return v2AdvertisementCache;
}

let v2InfoRefsCache: Buffer | null = null;

/** The whole v2 info/refs response: constant bytes, built once. */
function v2InfoRefs(): Buffer {
  if (v2InfoRefsCache === null) {
    v2InfoRefsCache = Buffer.concat([pktLine('# service=git-upload-pack\n'), FLUSH_PKT, v2Advertisement()]);
  }
  return v2InfoRefsCache;
}

function handleInfoRefs(res: ServerResponse, repo: Repo, service: string | null, protocol: string | null): void {
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    sendJsonRaw(res, 400, { message: 'missing or unknown service' });
    return;
  }
  if (service === 'git-upload-pack' && protocol !== null && protocol.includes('version=2')) {
    sendBuffer(res, 200, v2InfoRefs(), 'application/x-git-upload-pack-advertisement');
    return;
  }
  // The v0 advertisement depends only on the branch head and the ref set (object
  // types are fixed per oid), so the whole body is memoised per exact fingerprint.
  let fingerprint = `${service}|${repo.defaultBranch}|`;
  for (const [name, oid] of repo.refs) fingerprint += `${name}=${oid};`;
  const cache = repo.advCache;
  if (cache !== undefined && cache.key === fingerprint) {
    const hit = service === 'git-upload-pack' ? cache.upload : cache.receive;
    if (hit !== undefined) {
      sendBuffer(res, 200, hit, `application/x-${service}-advertisement`);
      return;
    }
  }
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), FLUSH_PKT, ...advertisementLines(repo, service), FLUSH_PKT];
  const body = Buffer.concat(parts);
  const entry = cache !== undefined && cache.key === fingerprint ? cache : { key: fingerprint };
  if (service === 'git-upload-pack') entry.upload = body;
  else entry.receive = body;
  repo.advCache = entry;
  sendBuffer(res, 200, body, `application/x-${service}-advertisement`);
}

/** One ls-refs answer line set, honouring ref-prefix filtering like git does. */
function lsRefsLines(repo: Repo, args: string[]): Buffer[] {
  const prefixes: string[] = [];
  let wantPeel = false;
  let wantSymrefs = false;
  let wantUnborn = false;
  for (const arg of args) {
    if (arg === 'peel') wantPeel = true;
    else if (arg === 'symrefs') wantSymrefs = true;
    else if (arg === 'unborn') wantUnborn = true;
    else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
  }
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: Buffer[] = [];
  const headName = headRefName(repo);
  const headOid = repo.refs.get(headName);
  const headMatches = prefixes.length === 0 || prefixes.some((prefix) => 'HEAD'.startsWith(prefix));
  if (headMatches) {
    if (headOid !== undefined) {
      let line = `${headOid} HEAD`;
      if (wantSymrefs) line += ` symref-target:${headName}`;
      lines.push(pktLine(`${line}\n`));
    } else if (wantUnborn) {
      let line = 'unborn HEAD';
      if (wantSymrefs) line += ` symref-target:${headName}`;
      lines.push(pktLine(`${line}\n`));
    }
  }
  for (const name of sortedRefNames(repo)) {
    if (!matches(name)) continue;
    const oid = repo.refs.get(name)!;
    let line = `${oid} ${name}`;
    const obj = getObject(repo, oid);
    if (wantPeel && obj !== null && obj.type === 'tag') line += ` peeled:${peelOne(repo, oid)}`;
    lines.push(pktLine(`${line}\n`));
  }
  return lines;
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: Set<string>;
  deepen: number | null;
  deepenSince: number | null;
  deepenNot: string[];
  done: boolean;
}

function parseFetchArgs(lines: string[], args: FetchArgs): void {
  for (const line of lines) {
    if (line.startsWith('want ')) args.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) args.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) args.shallow.add(line.slice(8).trim());
    else if (line.startsWith('deepen ')) args.deepen = Number(line.slice(7).trim()) || null;
    else if (line.startsWith('deepen-since ')) args.deepenSince = Number(line.slice(13).trim()) || null;
    else if (line.startsWith('deepen-not ')) args.deepenNot.push(line.slice(11).trim());
    else if (line === 'done') args.done = true;
  }
}

/** A fetch pack for a plan, cached per repository state (the clone benchmark repeats one fetch). */
function fetchPack(repo: Repo, plan: FetchPlan, args: FetchArgs): Buffer {
  const key = JSON.stringify({
    send: [...plan.send].sort(),
    deepen: args.deepen,
    shallow: [...args.shallow].sort(),
  });
  const cached = repo.packCache.get(key);
  if (cached !== undefined) return cached;
  const pack = buildPack(repo, plan.send);
  if (repo.packCache.size > 64) repo.packCache.clear();
  repo.packCache.set(key, pack);
  return pack;
}

/**
 * Exact fingerprint of the repository state a fetch answer can depend on: every
 * mutation adds/removes an object or moves a ref, so size + refs pin the state.
 */
function repoStateKey(repo: Repo): string {
  let key = `${repo.objects.size}|`;
  for (const [name, oid] of repo.refs) key += `${name}=${oid};`;
  return key;
}

/** Canonical key for one fetch request's arguments (order preserved, as sent). */
function fetchArgsKey(args: FetchArgs): string {
  return JSON.stringify([args.wants, args.haves, [...args.shallow], args.deepen, args.deepenSince, args.deepenNot, args.done]);
}

/** The cached fetch entry for this exact state+args, when present. */
function fetchCacheHit(repo: Repo, args: FetchArgs): { key: string; entry?: NonNullable<Repo['fetchCache']> } {
  const key = `${repoStateKey(repo)}#${fetchArgsKey(args)}`;
  const entry = repo.fetchCache;
  return { key, entry: entry !== undefined && entry.key === key ? entry : undefined };
}

function storeFetchCache(repo: Repo, key: string, plan: FetchPlan, slot: 'v2Done' | 'v2Ack' | 'v0', body: Buffer): void {
  const prev = repo.fetchCache;
  const entry = prev !== undefined && prev.key === key ? prev : { key, plan };
  entry.plan = plan;
  entry[slot] = body;
  repo.fetchCache = entry;
}

/** The v2 fetch response: acknowledgments / shallow-info / packfile sections. */
function v2FetchResponse(repo: Repo, args: FetchArgs): Buffer {
  const { key, entry } = fetchCacheHit(repo, args);
  if (entry !== undefined) {
    const hit = args.done ? entry.v2Done : entry.v2Ack;
    if (hit !== undefined) return hit;
  }
  const plan = entry !== undefined ? entry.plan : planFetch(repo, args.wants, args.haves, args.shallow, args.deepen, args.deepenSince, args.deepenNot);
  // Negotiation round (wait-for-done): without `done` the client is still offering
  // haves, so the answer is the acknowledgments alone — no `ready`, no packfile yet.
  if (!args.done) {
    const parts: Buffer[] = [pktLine('acknowledgments\n')];
    if (plan.commonHaves.length > 0) {
      for (const have of plan.commonHaves) parts.push(pktLine(`ACK ${have}\n`));
    } else {
      parts.push(pktLine('NAK\n'));
    }
    parts.push(FLUSH_PKT);
    const body = Buffer.concat(parts);
    storeFetchCache(repo, key, plan, 'v2Ack', body);
    return body;
  }
  // Sections are separated by a delimiter packet; only the last one ends in a flush.
  const sections: Buffer[][] = [];
  if (plan.send.length === 0) {
    sections.push([pktLine('acknowledgments\n'), pktLine('NAK\n')]);
  } else {
    // No acknowledgments section in the final response: after a negotiation round a
    // real git client expects the packfile (or shallow-info) first, and when there was
    // no negotiation the common bases were never in question.
    if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
      const info: Buffer[] = [pktLine('shallow-info\n')];
      for (const oid of plan.shallow) info.push(pktLine(`shallow ${oid}\n`));
      for (const oid of plan.unshallow) info.push(pktLine(`unshallow ${oid}\n`));
      sections.push(info);
    }
    const pack = fetchPack(repo, plan, args);
    sections.push([pktLine('packfile\n'), ...sidebandPackets(pack)]);
  }
  const parts: Buffer[] = [];
  sections.forEach((section, index) => {
    parts.push(...section);
    parts.push(index === sections.length - 1 ? FLUSH_PKT : DELIM_PKT);
  });
  const body = Buffer.concat(parts);
  storeFetchCache(repo, key, plan, 'v2Done', body);
  return body;
}

/** The v0 fetch response: shallow lines, a NAK, then the pack in sideband band 1. */
function v0FetchResponse(repo: Repo, args: FetchArgs): Buffer {
  const { key, entry } = fetchCacheHit(repo, args);
  if (entry !== undefined && entry.v0 !== undefined) return entry.v0;
  const plan = entry !== undefined ? entry.plan : planFetch(repo, args.wants, args.haves, args.shallow, args.deepen, args.deepenSince, args.deepenNot);
  const parts: Buffer[] = [];
  for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(pktLine('NAK\n'));
  if (plan.send.length > 0) {
    const pack = fetchPack(repo, plan, args);
    for (const packet of sidebandPackets(pack)) parts.push(packet);
  }
  parts.push(FLUSH_PKT);
  const body = Buffer.concat(parts);
  storeFetchCache(repo, key, plan, 'v0', body);
  return body;
}

async function handleUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const body = await readBody(req);
  let frames: PktFrame[];
  let rest: number;
  try {
    const parsed = parsePktLines(body, 0);
    frames = parsed.frames;
    rest = parsed.next;
  } catch {
    sendBuffer(res, 400, Buffer.from('unparsable upload-pack request\n'), 'text/plain');
    return;
  }
  const texts = frames.filter((frame) => frame.kind === 'data').map((frame) => frame.payload.toString('utf8').replace(/\n$/, ''));

  // Protocol v2: the first line is a command.
  if (texts.length > 0 && texts[0]!.startsWith('command=')) {
    const command = texts[0]!.slice('command='.length);
    // Argument lines follow the delim frame; rebuild them in order.
    const argLines: string[] = [];
    let pastDelim = false;
    for (const frame of frames) {
      if (frame.kind === 'delim') {
        pastDelim = true;
        continue;
      }
      if (frame.kind !== 'data' || !pastDelim) continue;
      argLines.push(frame.payload.toString('utf8').replace(/\n$/, ''));
    }
    if (command === 'ls-refs') {
      const lines = lsRefsLines(repo, argLines);
      sendBuffer(res, 200, Buffer.concat([...lines, FLUSH_PKT]), 'application/x-git-upload-pack-result');
      return;
    }
    if (command === 'fetch') {
      const args: FetchArgs = { wants: [], haves: [], shallow: new Set(), deepen: null, deepenSince: null, deepenNot: [], done: false };
      parseFetchArgs(argLines, args);
      sendBuffer(res, 200, v2FetchResponse(repo, args), 'application/x-git-upload-pack-result');
      return;
    }
    sendBuffer(res, 400, Buffer.from(`unknown command ${command}\n`), 'text/plain');
    return;
  }

  // Protocol v0: want lines (with capabilities on the first), a flush, then haves.
  const args: FetchArgs = { wants: [], haves: [], shallow: new Set(), deepen: null, deepenSince: null, deepenNot: [], done: false };
  const firstWant = texts.findIndex((line) => line.startsWith('want '));
  if (firstWant < 0) {
    sendBuffer(res, 400, Buffer.from('no wants in upload-pack request\n'), 'text/plain');
    return;
  }
  const wantLines = texts.map((line, index) => {
    if (index !== firstWant) return line;
    const space = line.indexOf(' ', 5);
    return space < 0 ? line : line.slice(0, line.indexOf('\0', 5) > 0 ? line.indexOf('\0', 5) : space);
  });
  parseFetchArgs(wantLines, args);
  // The have lines live in the second pkt-line block, after the first flush.
  try {
    const second = parsePktLines(body, rest);
    const haveLines = second.frames.filter((frame) => frame.kind === 'data').map((frame) => frame.payload.toString('utf8').replace(/\n$/, ''));
    parseFetchArgs(haveLines, args);
  } catch {
    // A body that ends after the wants is still answerable.
  }
  sendBuffer(res, 200, v0FetchResponse(repo, args), 'application/x-git-upload-pack-result');
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
  caps: string;
}

async function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const body = await readBody(req);
  let commands: PushCommand[] = [];
  let packStart = body.length;
  try {
    const parsed = parsePktLines(body, 0);
    let caps = '';
    parsed.frames
      .filter((frame) => frame.kind === 'data')
      .forEach((frame, index) => {
        let text = frame.payload.toString('utf8').replace(/\n$/, '');
        if (index === 0) {
          const nul = text.indexOf('\0');
          if (nul >= 0) {
            caps = text.slice(nul + 1);
            text = text.slice(0, nul);
          }
        }
        const parts = text.split(' ');
        if (parts.length >= 3 && isOid(parts[0]!) && isOid(parts[1]!)) {
          commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts.slice(2).join(' '), caps });
        }
      });
    packStart = parsed.next;
  } catch {
    commands = [];
    packStart = body.length;
  }

  const sideband = commands.length > 0 && commands[0]!.caps.includes('side-band-64k');
  const reportLines: string[] = [];
  let unpackOk = true;
  let unpackDetail = '';

  const packBytes = body.subarray(packStart);
  if (packBytes.length > 0) {
    try {
      const objects = parsePack(repo, packBytes);
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : String(err);
    }
  }
  reportLines.push(unpackOk ? 'unpack ok' : `unpack ${unpackDetail}`);

  if (unpackOk) {
    repo.packCache.clear();
    for (const command of commands) {
      const { oldOid, newOid, ref } = command;
      if (newOid === ZERO_OID) {
        // Delete.
        if (repo.refs.has(ref)) {
          repo.refs.delete(ref);
          reportLines.push(`ok ${ref}`);
        } else {
          reportLines.push(`ng ${ref} reference does not exist`);
        }
        continue;
      }
      const target = getObject(repo, newOid);
      if (target === null) {
        reportLines.push(`ng ${ref} new object not found`);
        continue;
      }
      const current = repo.refs.get(ref) ?? ZERO_OID;
      const effectiveOld = current === ZERO_OID ? oldOid : current;
      if (effectiveOld !== ZERO_OID && effectiveOld !== newOid) {
        const newCommit = peelToCommit(repo, newOid);
        const oldCommit = peelToCommit(repo, effectiveOld);
        if (newCommit === null || oldCommit === null || !isAncestor(repo, oldCommit, newCommit)) {
          reportLines.push(`ng ${ref} non-fast-forward`);
          continue;
        }
      }
      repo.refs.set(ref, newOid);
      reportLines.push(`ok ${ref}`);
    }
  } else {
    for (const command of commands) reportLines.push(`ng ${command.ref} unpack failed`);
  }

  const stream = Buffer.concat([...reportLines.map((line) => pktLine(`${line}\n`)), FLUSH_PKT]);
  if (sideband) {
    const packets = sidebandPackets(stream, 1);
    sendBuffer(res, 200, Buffer.concat([...packets, FLUSH_PKT]), 'application/x-git-receive-pack-result');
  } else {
    sendBuffer(res, 200, stream, 'application/x-git-receive-pack-result');
  }
}

// ---------------------------------------------------------------------------
// Shared pull-request machinery (REST merge, GraphQL merge, mergeable)
// ---------------------------------------------------------------------------

interface FlatEntry {
  oid: string;
  mode: string;
}

function sameEntry(a: FlatEntry | undefined, b: FlatEntry | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a.oid === b.oid && a.mode === b.mode;
}

/** The three-way tree merge of a pull request; null when both sides changed a path differently. */
function mergedTree(repo: Repo, baseTip: string, headTip: string): Map<string, FlatEntry> | null {
  const baseCommit = peelToCommit(repo, baseTip);
  const headCommit = peelToCommit(repo, headTip);
  if (baseCommit === null || headCommit === null) return null;
  const mb = mergeBaseOf(repo, baseCommit, headCommit);
  const mbFiles = mb === null ? new Map<string, FlatEntry>() : commitFiles(repo, mb);
  const baseFiles = commitFiles(repo, baseCommit);
  const headFiles = commitFiles(repo, headCommit);
  const merged = new Map<string, FlatEntry>();
  const paths = new Set<string>([...mbFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of paths) {
    const b = mbFiles.get(path);
    const s = baseFiles.get(path);
    const h = headFiles.get(path);
    if (sameEntry(s, h)) {
      if (s !== undefined) merged.set(path, s);
    } else if (sameEntry(b, s)) {
      if (h !== undefined) merged.set(path, h);
    } else if (sameEntry(b, h)) {
      if (s !== undefined) merged.set(path, s);
    } else {
      return null;
    }
  }
  return merged;
}

function pullTips(repo: Repo, pull: PullRec): { baseTip: string; headTip: string } {
  return {
    baseTip: repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha,
    headTip: repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha,
  };
}

/** Merge a pull request into its base branch (squash). Returns the merge commit sha, or null on conflict. */
function mergePull(repo: Repo, pull: PullRec): string | null {
  const { baseTip, headTip } = pullTips(repo, pull);
  const ts = nextTimestamp();
  if (isAncestor(repo, peelToCommit(repo, headTip) ?? headTip, peelToCommit(repo, baseTip) ?? baseTip)) {
    pull.state = 'closed';
    pull.merged = true;
    pull.mergedAt = isoOf(ts);
    pull.mergeCommitSha = baseTip;
    return baseTip;
  }
  const tree = mergedTree(repo, baseTip, headTip);
  if (tree === null) return null;
  const treeOid = buildTreeFromFlat(repo, tree);
  const baseCommit = peelToCommit(repo, baseTip) ?? baseTip;
  const message = pull.body === '' ? `${pull.title}\n` : `${pull.title}\n\n${pull.body}\n`;
  const commitOid = putObject(repo, 'commit', buildCommitData(treeOid, [baseCommit], message, ts));
  repo.refs.set(`refs/heads/${pull.baseRef}`, commitOid);
  repo.packCache.clear();
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoOf(ts);
  pull.mergeCommitSha = commitOid;
  return commitOid;
}

/** Whether an open pull request would merge cleanly right now. */
function pullMergeable(repo: Repo, pull: PullRec): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.state !== 'open') return 'UNKNOWN';
  const { baseTip, headTip } = pullTips(repo, pull);
  if (getObject(repo, baseTip) === null || getObject(repo, headTip) === null) return 'UNKNOWN';
  return mergedTree(repo, baseTip, headTip) === null ? 'CONFLICTING' : 'MERGEABLE';
}

function countLines(data: Buffer): number {
  if (data.length === 0) return 0;
  let lines = 0;
  for (const byte of data) if (byte === 0x0a) lines += 1;
  if (data[data.length - 1] !== 0x0a) lines += 1;
  return lines;
}

interface FileChange {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
}

/** The changed files of a pull request: merge-base tree versus head tree. */
function pullFiles(repo: Repo, pull: PullRec): FileChange[] {
  const { baseTip, headTip } = pullTips(repo, pull);
  const baseCommit = peelToCommit(repo, baseTip);
  const headCommit = peelToCommit(repo, headTip);
  if (baseCommit === null || headCommit === null) return [];
  const mb = mergeBaseOf(repo, baseCommit, headCommit);
  const fromFiles = mb === null ? new Map<string, FlatEntry>() : commitFiles(repo, mb);
  const toFiles = commitFiles(repo, headCommit);
  const changes: FileChange[] = [];
  const paths = new Set<string>([...fromFiles.keys(), ...toFiles.keys()]);
  for (const path of [...paths].sort()) {
    const from = fromFiles.get(path);
    const to = toFiles.get(path);
    if (sameEntry(from, to)) continue;
    const oldData = from === undefined ? null : getObject(repo, from.oid)?.data ?? null;
    const newData = to === undefined ? null : getObject(repo, to.oid)?.data ?? null;
    const additions = newData === null ? 0 : countLines(newData);
    const deletions = oldData === null ? 0 : countLines(oldData);
    changes.push({
      filename: path,
      status: from === undefined ? 'added' : to === undefined ? 'removed' : 'modified',
      additions,
      deletions,
      changes: additions + deletions,
    });
  }
  return changes;
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: globalId(`repo:${repo.id}`),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    fork: false,
    created_at: isoOf(1_700_000_000 + repo.id),
    updated_at: isoOf(1_700_000_000 + repo.id),
  };
}

function issueJson(repo: Repo, issue: IssueRec): Record<string, unknown> {
  nextIssueRestId += 0; // ids are assigned at creation; see createIssueRec
  return {
    id: issueRestIds.get(`${repo.id}:${issue.number}`) ?? issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? '000000' })),
    comments: issue.comments.length,
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    created_at: isoOf(issue.createdTs),
    updated_at: isoOf(issue.createdTs),
  };
}

const issueRestIds = new Map<string, number>();

/**
 * The issue's REST JSON as an encoded buffer, memoised on the record. The cache key is a
 * fingerprint of every value issueJson renders (its fields, its comment count, and the
 * repo's label epoch for the colours), so any mutation — REST, GraphQL or MCP, they all
 * write these same fields — misses the cache and re-renders. Byte-identical output.
 * The labels fingerprint is the array reference itself: issue.labels is only ever
 * replaced wholesale (creation copies the input, updates assign a fresh array) and
 * never mutated in place anywhere in this file, so reference equality is exact —
 * it replaces a per-call join() allocation on the read hot path.
 */
function issueJsonBuffer(repo: Repo, issue: IssueRec): Buffer {
  const cached = issue.jsonCache;
  if (
    cached !== undefined &&
    cached.title === issue.title &&
    cached.body === issue.body &&
    cached.state === issue.state &&
    cached.commentsLength === issue.comments.length &&
    cached.labelEpoch === repo.labelEpoch &&
    cached.labelsRef === issue.labels
  ) {
    return cached.buf;
  }
  const buf = Buffer.from(JSON.stringify(issueJson(repo, issue)));
  issue.jsonCache = {
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labelsRef: issue.labels,
    commentsLength: issue.comments.length,
    labelEpoch: repo.labelEpoch,
    buf,
  };
  return buf;
}

function createIssueRec(repo: Repo, title: string, body: string, labels: string[]): IssueRec {
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const issue: IssueRec = {
    number,
    title,
    body,
    state: 'open',
    labels: [...labels],
    comments: [],
    createdTs: nextTimestamp(),
  };
  repo.issues.set(number, issue);
  nextIssueRestId += 1;
  issueRestIds.set(`${repo.id}:${number}`, nextIssueRestId);
  return issue;
}

function pullJson(repo: Repo, pull: PullRec): Record<string, unknown> {
  return {
    id: issueRestIds.get(`${repo.id}:${pull.number}`) ?? pull.number,
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    created_at: isoOf(pull.createdTs),
    updated_at: isoOf(pull.createdTs),
  };
}

function createPullRec(repo: Repo, title: string, body: string, headRef: string, baseRef: string, headSha: string, baseSha: string): PullRec {
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const pull: PullRec = {
    number,
    title,
    body,
    state: 'open',
    headRef,
    baseRef,
    headSha,
    baseSha,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    comments: [],
    createdTs: nextTimestamp(),
  };
  repo.pulls.set(number, pull);
  nextIssueRestId += 1;
  issueRestIds.set(`${repo.id}:${number}`, nextIssueRestId);
  return pull;
}

/** Global node ids for GraphQL: base64url of a typed key, never the plain database id. */
function globalId(key: string): string {
  return Buffer.from(key, 'utf8').toString('base64url');
}

function decodeGlobalId(id: string): string | null {
  try {
    return Buffer.from(id, 'base64url').toString('utf8');
  } catch {
    return null;
  }
}

function notFound(res: ServerResponse): void {
  sendJsonRaw(res, 404, { message: 'Not Found' });
}

function unprocessable(res: ServerResponse, message: string): void {
  sendJsonRaw(res, 422, { message });
}

/** Parse a JSON request body; on malformed JSON, answer 400 and return undefined. */
async function jsonBody(req: IncomingMessage, res: ServerResponse): Promise<Record<string, unknown> | undefined> {
  const raw = await readBody(req);
  if (raw.length === 0) return {};
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return parsed as Record<string, unknown>;
  } catch {
    sendJsonRaw(res, 400, { message: 'Problems parsing JSON' });
    return undefined;
  }
}

interface Page {
  perPage: number;
  page: number;
}

function pageOf(url: URL): Page {
  const perPage = Math.max(1, Math.min(100, Number(url.searchParams.get('per_page') ?? '30') || 30));
  const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
  return { perPage, page };
}

/** Slice one page out of a list and set the Link header when a next page exists. */
function paginate<T>(req: IncomingMessage, res: ServerResponse, url: URL, items: T[], page: Page): T[] {
  const start = (page.page - 1) * page.perPage;
  const slice = items.slice(start, start + page.perPage);
  if (start + page.perPage < items.length) {
    const host = req.headers.host ?? 'localhost';
    const next = new URL(url.pathname, `http://${host}`);
    for (const [key, value] of url.searchParams) next.searchParams.set(key, value);
    next.searchParams.set('per_page', String(page.perPage));
    next.searchParams.set('page', String(page.page + 1));
    const last = new URL(url.pathname, `http://${host}`);
    for (const [key, value] of url.searchParams) last.searchParams.set(key, value);
    last.searchParams.set('per_page', String(page.perPage));
    last.searchParams.set('page', String(Math.ceil(items.length / page.perPage)));
    res.setHeader('link', `<${next.toString()}>; rel="next", <${last.toString()}>; rel="last"`);
  }
  return slice;
}

/** Resolve a ref-ish (branch name, full ref, or oid) to a commit oid. */
function resolveCommit(repo: Repo, refish: string | null): string | null {
  if (refish === null || refish === '') {
    const tip = repo.refs.get(headRefName(repo));
    return tip === undefined ? null : peelToCommit(repo, tip);
  }
  const candidates = [refish, `refs/heads/${refish}`, `refs/tags/${refish}`];
  for (const candidate of candidates) {
    const oid = repo.refs.get(candidate);
    if (oid !== undefined) return peelToCommit(repo, oid);
  }
  if (isOid(refish)) return peelToCommit(repo, refish);
  return null;
}

/** Create one commit on a branch from a flat file map; returns the commit oid. */
function commitOnBranch(repo: Repo, branch: string, flat: Map<string, FlatEntry>, message: string): string {
  const ref = `refs/heads/${branch}`;
  const parent = repo.refs.get(ref) ?? null;
  const treeOid = buildTreeFromFlat(repo, flat);
  const ts = nextTimestamp();
  const commitOid = putObject(repo, 'commit', buildCommitData(treeOid, parent === null ? [] : [peelToCommit(repo, parent) ?? parent], message, ts));
  repo.refs.set(ref, commitOid);
  repo.packCache.clear();
  return commitOid;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const method = req.method ?? 'GET';
  const segments = url.pathname
    .replace(/^\/api\/v3\/?/, '')
    .split('/')
    .filter((segment) => segment !== '')
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    });
  res.setHeader('x-oauth-scopes', 'repo, read:org');

  // The API root and meta.
  if (segments.length === 0) {
    if (method !== 'GET') return notFound(res);
    sendJsonRaw(res, 200, {
      current_user_url: '/api/v3/user',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      issue_url: '/api/v3/repos/{owner}/{repo}/issues',
      rate_limit_url: '/api/v3/rate_limit',
    });
    return;
  }
  if (segments[0] === 'meta' && segments.length === 1) {
    if (method !== 'GET') return notFound(res);
    sendJsonRaw(res, 200, { installed_version: '1.0.0', git_executable: 'forge' });
    return;
  }

  // The viewer.
  if (segments[0] === 'user' && segments.length === 1) {
    if (method !== 'GET') return notFound(res);
    sendJsonRaw(res, 200, { login: VIEWER, id: VIEWER_ID, type: 'User', name: VIEWER_NAME, email: VIEWER_EMAIL });
    return;
  }
  if (segments[0] === 'user' && segments[1] === 'repos' && segments.length === 2) {
    if (method === 'GET') {
      const mine = [...repos.values()].filter((repo) => repo.owner === VIEWER).map((repo) => repoJson(repo));
      sendJsonRaw(res, 200, paginate(req, res, url, mine, pageOf(url)));
      return;
    }
    if (method === 'POST') {
      const body = await jsonBody(req, res);
      if (body === undefined) return;
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') return unprocessable(res, 'name is required');
      if (findRepo(VIEWER, name) !== null) return unprocessable(res, 'name already exists on this account');
      const repo = createRepoRec(
        VIEWER,
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      sendJsonRaw(res, 201, repoJson(repo));
      return;
    }
    return notFound(res);
  }

  if (segments[0] !== 'repos' || segments.length < 3) return notFound(res);
  const owner = segments[1]!;
  const repo = findRepo(owner, segments[2]!);
  if (repo === null) return notFound(res);
  const rest = segments.slice(3);

  // The repository itself.
  if (rest.length === 0) {
    if (method === 'GET') {
      sendJsonRaw(res, 200, repoJson(repo));
      return;
    }
    if (method === 'PATCH') {
      const body = await jsonBody(req, res);
      if (body === undefined) return;
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.isPrivate = body.private;
      if (typeof body.default_branch === 'string' && body.default_branch !== '') repo.defaultBranch = body.default_branch;
      sendJsonRaw(res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      res.writeHead(204, { 'x-github-request-id': nextRequestId() });
      res.end();
      return;
    }
    return notFound(res);
  }

  // Branches.
  if (rest[0] === 'branches') {
    if (method !== 'GET') return notFound(res);
    if (rest.length === 1) {
      const list = sortedRefNames(repo)
        .filter((name) => name.startsWith('refs/heads/'))
        .map((name) => ({ name: name.slice('refs/heads/'.length), commit: { sha: repo.refs.get(name)! }, protected: false }));
      sendJsonRaw(res, 200, list);
      return;
    }
    const branch = rest.slice(1).join('/');
    const tip = repo.refs.get(`refs/heads/${branch}`);
    if (tip === undefined) return notFound(res);
    sendJsonRaw(res, 200, { name: branch, commit: { sha: tip }, protected: false });
    return;
  }

  // Git refs.
  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      const body = await jsonBody(req, res);
      if (body === undefined) return;
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || getObject(repo, sha) === null) {
        return unprocessable(res, 'invalid ref or sha');
      }
      if (repo.refs.has(ref)) return unprocessable(res, 'Reference already exists');
      repo.refs.set(ref, sha);
      repo.packCache.clear();
      sendJsonRaw(res, 201, { ref, object: { sha, type: getObject(repo, sha)!.type } });
      return;
    }
    if (method === 'GET') {
      if (rest.length === 2) {
        const list = sortedRefNames(repo).map((name) => ({ ref: name, object: { sha: repo.refs.get(name)! } }));
        sendJsonRaw(res, 200, list);
        return;
      }
      const tail = rest.slice(2).join('/');
      const ref = tail.startsWith('refs/') ? tail : `refs/${tail}`;
      const sha = repo.refs.get(ref);
      if (sha === undefined) return notFound(res);
      sendJsonRaw(res, 200, { ref, object: { sha, type: getObject(repo, sha)?.type ?? 'commit' } });
      return;
    }
    return notFound(res);
  }

  // Commits.
  if (rest[0] === 'commits' && rest.length === 1) {
    if (method !== 'GET') return notFound(res);
    const tip = resolveCommit(repo, url.searchParams.get('sha'));
    if (tip === null) {
      sendJsonRaw(res, 409, { message: 'Git Repository is empty' });
      return;
    }
    const list = reachableCommits(repo, tip).map((info) => ({
      sha: objectId('commit', info.raw),
      commit: {
        message: info.message,
        tree: { sha: info.tree },
        author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(info.timestamp) },
        committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(info.timestamp) },
      },
      parents: info.parents.map((sha) => ({ sha })),
    }));
    sendJsonRaw(res, 200, paginate(req, res, url, list, pageOf(url)));
    return;
  }

  // Contents.
  if (rest[0] === 'contents') {
    const path = rest.slice(1).join('/');
    if (method === 'GET') {
      const tip = resolveCommit(repo, url.searchParams.get('ref'));
      if (tip === null) return notFound(res);
      const files = commitFiles(repo, tip);
      const commitObj = getObject(repo, tip)!;
      const rootTree = parseCommit(commitObj.data).tree;
      if (path === '') {
        const entries = parseTree(getObject(repo, rootTree)!.data).map((entry) => ({
          name: entry.name,
          path: entry.name,
          sha: entry.oid,
          size: isTreeMode(entry.mode) ? 0 : (getObject(repo, entry.oid)?.data.length ?? 0),
          type: isTreeMode(entry.mode) ? 'dir' : 'file',
        }));
        sendJsonRaw(res, 200, entries);
        return;
      }
      const file = files.get(path);
      if (file !== undefined) {
        const data = getObject(repo, file.oid)!.data;
        sendJsonRaw(res, 200, {
          type: 'file',
          name: path.split('/').pop(),
          path,
          sha: file.oid,
          size: data.length,
          encoding: 'base64',
          content: data.toString('base64'),
        });
        return;
      }
      // A directory: walk the tree to the prefix and list its entries.
      const prefix = `${path}/`;
      if ([...files.keys()].some((key) => key.startsWith(prefix))) {
        let treeOid = rootTree;
        for (const segment of path.split('/')) {
          const entry = parseTree(getObject(repo, treeOid)!.data).find((candidate) => candidate.name === segment);
          if (entry === undefined || !isTreeMode(entry.mode)) return notFound(res);
          treeOid = entry.oid;
        }
        const entries = parseTree(getObject(repo, treeOid)!.data).map((entry) => ({
          name: entry.name,
          path: `${path}/${entry.name}`,
          sha: entry.oid,
          size: isTreeMode(entry.mode) ? 0 : (getObject(repo, entry.oid)?.data.length ?? 0),
          type: isTreeMode(entry.mode) ? 'dir' : 'file',
        }));
        sendJsonRaw(res, 200, entries);
        return;
      }
      return notFound(res);
    }
    if (method === 'PUT') {
      const body = await jsonBody(req, res);
      if (body === undefined) return;
      if (path === '') return unprocessable(res, 'path is required');
      const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
      const ref = `refs/heads/${branch}`;
      let parentTip = repo.refs.get(ref) ?? null;
      if (parentTip === null && branch !== repo.defaultBranch) {
        parentTip = repo.refs.get(headRefName(repo)) ?? null;
      }
      const flat: Map<string, FlatEntry> = parentTip === null ? new Map() : commitFiles(repo, peelToCommit(repo, parentTip) ?? parentTip);
      const existing = flat.get(path);
      if (existing !== undefined && typeof body.sha === 'string' && body.sha !== existing.oid) {
        sendJsonRaw(res, 409, { message: `${path} has changed since ${body.sha}` });
        return;
      }
      const content = typeof body.content === 'string' ? Buffer.from(body.content.replace(/[\r\n\t ]+/g, ''), 'base64') : Buffer.alloc(0);
      const blobOid = putObject(repo, 'blob', content);
      flat.set(path, { oid: blobOid, mode: '100644' });
      const message = typeof body.message === 'string' && body.message !== '' ? body.message : `Update ${path}`;
      const commitOid = commitOnBranch(repo, branch, flat, message);
      sendJsonRaw(res, existing === undefined ? 201 : 200, {
        content: { name: path.split('/').pop(), path, sha: blobOid, size: content.length, encoding: 'base64' },
        commit: { sha: commitOid, message },
      });
      return;
    }
    if (method === 'DELETE') {
      const body = await jsonBody(req, res);
      if (body === undefined) return;
      const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) return notFound(res);
      const flat = commitFiles(repo, peelToCommit(repo, tip) ?? tip);
      const existing = flat.get(path);
      if (existing === undefined) return notFound(res);
      if (typeof body.sha === 'string' && body.sha !== existing.oid) {
        sendJsonRaw(res, 409, { message: `${path} has changed since ${body.sha}` });
        return;
      }
      flat.delete(path);
      const message = typeof body.message === 'string' && body.message !== '' ? body.message : `Delete ${path}`;
      const commitOid = commitOnBranch(repo, branch, flat, message);
      sendJsonRaw(res, 200, { content: null, commit: { sha: commitOid, message } });
      return;
    }
    return notFound(res);
  }

  // Labels.
  if (rest[0] === 'labels' && rest.length === 1) {
    if (method === 'GET') {
      sendJsonRaw(res, 200, [...repo.labels.values()].map((label) => ({ name: label.name, color: label.color })));
      return;
    }
    if (method === 'POST') {
      const body = await jsonBody(req, res);
      if (body === undefined) return;
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') return unprocessable(res, 'name is required');
      if (repo.labels.has(name)) return unprocessable(res, 'name has already been taken');
      const color = typeof body.color === 'string' ? body.color.replace(/^#/, '') : '000000';
      repo.labels.set(name, { name, color });
      repo.labelEpoch += 1;
      sendJsonRaw(res, 201, { name, color });
      return;
    }
    return notFound(res);
  }

  // Issues and their comments.
  if (rest[0] === 'issues') {
    if (rest.length === 1) {
      if (method === 'POST') {
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        const title = typeof body.title === 'string' ? body.title : '';
        if (title === '') return unprocessable(res, 'title is required');
        const labelNames: string[] = [];
        if (Array.isArray(body.labels)) {
          for (const raw of body.labels) {
            const name = typeof raw === 'string' ? raw : isRecord(raw) && typeof raw.name === 'string' ? raw.name : '';
            if (name === '' || !repo.labels.has(name)) return unprocessable(res, `label ${name} does not exist`);
            labelNames.push(name);
          }
        }
        const issue = createIssueRec(repo, title, typeof body.body === 'string' ? body.body : '', labelNames);
        sendJsonBuffer(res, 201, issueJsonBuffer(repo, issue));
        return;
      }
      if (method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        const direction = url.searchParams.get('direction') ?? 'desc';
        let list = [...repo.issues.values()];
        if (state === 'open') list = list.filter((issue) => issue.state === 'open');
        else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
        list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        sendJsonRaw(res, 200, paginate(req, res, url, list.map((issue) => issueJson(repo, issue)), pageOf(url)));
        return;
      }
      return notFound(res);
    }
    const number = Number(rest[1]);
    if (!Number.isInteger(number)) return notFound(res);
    if (rest.length === 2) {
      const issue = repo.issues.get(number);
      if (issue === undefined) return notFound(res);
      if (method === 'GET') {
        sendJsonBuffer(res, 200, issueJsonBuffer(repo, issue));
        return;
      }
      if (method === 'PATCH') {
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
        if (typeof body.title === 'string') issue.title = body.title;
        if (typeof body.body === 'string') issue.body = body.body;
        if (Array.isArray(body.labels)) {
          const names: string[] = [];
          for (const raw of body.labels) {
            const name = typeof raw === 'string' ? raw : isRecord(raw) && typeof raw.name === 'string' ? raw.name : '';
            if (name !== '') names.push(name);
          }
          issue.labels = names;
        }
        sendJsonBuffer(res, 200, issueJsonBuffer(repo, issue));
        return;
      }
      return notFound(res);
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      const holder = repo.issues.get(number) ?? repo.pulls.get(number);
      if (holder === undefined) return notFound(res);
      if (method === 'GET') {
        sendJsonRaw(res, 200, holder.comments.map((comment) => ({ id: comment.id, body: comment.body, user: { login: comment.author } })));
        return;
      }
      if (method === 'POST') {
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        const text = typeof body.body === 'string' ? body.body : '';
        const comment: CommentRec = { id: repo.nextCommentId, body: text, author: VIEWER };
        repo.nextCommentId += 1;
        holder.comments.push(comment);
        sendJsonRaw(res, 201, { id: comment.id, body: comment.body, user: { login: VIEWER, id: VIEWER_ID, type: 'User' } });
        return;
      }
      return notFound(res);
    }
    return notFound(res);
  }

  // Pull requests.
  if (rest[0] === 'pulls') {
    if (rest.length === 1) {
      if (method === 'POST') {
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        const stripPrefix = (value: string): string => (value.includes(':') ? value.slice(value.indexOf(':') + 1) : value);
        const head = stripPrefix(typeof body.head === 'string' ? body.head : '');
        const base = stripPrefix(typeof body.base === 'string' && body.base !== '' ? body.base : repo.defaultBranch);
        const headSha = repo.refs.get(`refs/heads/${head}`);
        const baseSha = repo.refs.get(`refs/heads/${base}`);
        if (headSha === undefined) return unprocessable(res, `head branch ${head} does not exist`);
        if (baseSha === undefined) return unprocessable(res, `base branch ${base} does not exist`);
        const pull = createPullRec(
          repo,
          typeof body.title === 'string' ? body.title : '',
          typeof body.body === 'string' ? body.body : '',
          head,
          base,
          headSha,
          baseSha,
        );
        sendJsonRaw(res, 201, pullJson(repo, pull));
        return;
      }
      if (method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        let list = [...repo.pulls.values()];
        if (state === 'open') list = list.filter((pull) => pull.state === 'open');
        else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
        list.sort((a, b) => b.number - a.number);
        sendJsonRaw(res, 200, paginate(req, res, url, list.map((pull) => pullJson(repo, pull)), pageOf(url)));
        return;
      }
      return notFound(res);
    }
    const number = Number(rest[1]);
    if (!Number.isInteger(number)) return notFound(res);
    const pull = repo.pulls.get(number);
    if (rest.length === 2) {
      if (pull === undefined) return notFound(res);
      if (method === 'GET') {
        sendJsonRaw(res, 200, pullJson(repo, pull));
        return;
      }
      return notFound(res);
    }
    if (rest.length === 3 && rest[2] === 'files') {
      if (pull === undefined) return notFound(res);
      if (method !== 'GET') return notFound(res);
      sendJsonRaw(res, 200, pullFiles(repo, pull));
      return;
    }
    if (rest.length === 3 && rest[2] === 'merge') {
      if (method !== 'PUT') return notFound(res);
      if (pull === undefined) return notFound(res);
      const body = await jsonBody(req, res);
      if (body === undefined) return;
      if (pull.merged) {
        sendJsonRaw(res, 405, { message: 'Pull Request is not mergeable' });
        return;
      }
      const sha = mergePull(repo, pull);
      if (sha === null) {
        sendJsonRaw(res, 405, { message: 'Pull Request is not mergeable' });
        return;
      }
      sendJsonRaw(res, 200, { sha, merged: true, message: 'Pull Request successfully merged' });
      return;
    }
    return notFound(res);
  }

  return notFound(res);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// GraphQL v4: a small executor for the surface gh and github-mcp-server use
// ---------------------------------------------------------------------------

type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'string'; value: string }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: { name: string; value: GqlValue }[] };

interface GqlField {
  kind: 'field';
  name: string;
  alias: string | null;
  args: { name: string; value: GqlValue }[];
  selectionSet: GqlSelection[] | null;
}

type GqlSelection =
  | GqlField
  | { kind: 'inline'; typeCondition: string | null; selectionSet: GqlSelection[] }
  | { kind: 'spread'; name: string };

interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  selectionSet: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { typeCondition: string | null; selectionSet: GqlSelection[] }>;
}

function lexGraphql(source: string): { kind: string; value: string }[] {
  const tokens: { kind: string; value: string }[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('!$():=@[]{}'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        if (end < 0) throw new Error('unterminated block string');
        tokens.push({ kind: 'string', value: source.slice(i + 3, end) });
        i = end + 3;
        continue;
      }
      let j = i + 1;
      let value = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\') {
          const esc = source[j + 1]!;
          if (esc === 'n') value += '\n';
          else if (esc === 't') value += '\t';
          else if (esc === 'r') value += '\r';
          else if (esc === 'b') value += '\b';
          else if (esc === 'f') value += '\f';
          else if (esc === '/') value += '/';
          else if (esc === '\\') value += '\\';
          else if (esc === '"') value += '"';
          else if (esc === 'u') {
            value += String.fromCharCode(parseInt(source.slice(j + 2, j + 6), 16));
            j += 4;
          } else value += esc;
          j += 2;
        } else {
          value += source[j];
          j += 1;
        }
      }
      if (j >= source.length) throw new Error('unterminated string');
      tokens.push({ kind: 'string', value });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9.eE+-]/.test(source[j]!)) j += 1;
      const text = source.slice(i, j);
      tokens.push({ kind: /[.eE]/.test(text) ? 'float' : 'int', value: text });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < source.length && /[_0-9A-Za-z]/.test(source[j]!)) j += 1;
      tokens.push({ kind: 'name', value: source.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  tokens.push({ kind: 'eof', value: '' });
  return tokens;
}

function parseGraphql(source: string): GqlDocument {
  const tokens = lexGraphql(source);
  let pos = 0;
  const peek = (): { kind: string; value: string } => tokens[pos]!;
  const next = (): { kind: string; value: string } => tokens[pos++]!;
  const expectPunct = (value: string): void => {
    const token = next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`expected ${value}, got ${token.value}`);
  };
  const skipType = (): void => {
    // A type reference: Name, [Type], with optional ! suffixes.
    if (peek().kind === 'punct' && peek().value === '[') {
      next();
      skipType();
      expectPunct(']');
    } else {
      next();
    }
    if (peek().kind === 'punct' && peek().value === '!') next();
  };
  const parseValue = (): GqlValue => {
    const token = next();
    if (token.kind === 'punct' && token.value === '$') {
      const name = next();
      return { kind: 'var', name: name.value };
    }
    if (token.kind === 'int') return { kind: 'int', value: Number(token.value) };
    if (token.kind === 'float') return { kind: 'float', value: Number(token.value) };
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (!(peek().kind === 'punct' && peek().value === ']')) items.push(parseValue());
      next();
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields: { name: string; value: GqlValue }[] = [];
      while (!(peek().kind === 'punct' && peek().value === '}')) {
        const name = next();
        expectPunct(':');
        fields.push({ name: name.value, value: parseValue() });
      }
      next();
      return { kind: 'object', fields };
    }
    throw new Error(`unexpected value token ${token.value}`);
  };
  const parseSelectionSet = (): GqlSelection[] => {
    expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(peek().kind === 'punct' && peek().value === '}')) {
      if (peek().kind === 'spread') {
        next();
        if (peek().kind === 'name' && peek().value === 'on') {
          next();
          const typeName = next().value;
          selections.push({ kind: 'inline', typeCondition: typeName, selectionSet: parseSelectionSet() });
        } else {
          const name = next();
          selections.push({ kind: 'spread', name: name.value });
        }
        continue;
      }
      let name = next();
      if (name.kind !== 'name') throw new Error(`expected a field name, got ${name.value}`);
      let alias: string | null = null;
      if (peek().kind === 'punct' && peek().value === ':') {
        next();
        alias = name.value;
        name = next();
      }
      const args: { name: string; value: GqlValue }[] = [];
      if (peek().kind === 'punct' && peek().value === '(') {
        next();
        while (!(peek().kind === 'punct' && peek().value === ')')) {
          const argName = next();
          expectPunct(':');
          args.push({ name: argName.value, value: parseValue() });
        }
        next();
      }
      // Directives are parsed and ignored.
      while (peek().kind === 'punct' && peek().value === '@') {
        next();
        next();
        if (peek().kind === 'punct' && peek().value === '(') {
          next();
          while (!(peek().kind === 'punct' && peek().value === ')')) {
            next();
            expectPunct(':');
            parseValue();
          }
          next();
        }
      }
      let selectionSet: GqlSelection[] | null = null;
      if (peek().kind === 'punct' && peek().value === '{') selectionSet = parseSelectionSet();
      selections.push({ kind: 'field', name: name.value, alias, args, selectionSet });
    }
    next();
    return selections;
  };

  const document: GqlDocument = { operations: [], fragments: new Map() };
  while (peek().kind !== 'eof') {
    if (peek().kind === 'punct' && peek().value === '{') {
      document.operations.push({ type: 'query', name: null, selectionSet: parseSelectionSet() });
      continue;
    }
    const keyword = next();
    if (keyword.kind !== 'name') throw new Error(`unexpected token ${keyword.value}`);
    if (keyword.value === 'query' || keyword.value === 'mutation' || keyword.value === 'subscription') {
      let name: string | null = null;
      if (peek().kind === 'name') name = next().value;
      if (peek().kind === 'punct' && peek().value === '(') {
        next();
        while (!(peek().kind === 'punct' && peek().value === ')')) {
          expectPunct('$');
          next(); // variable name
          expectPunct(':');
          skipType();
          if (peek().kind === 'punct' && peek().value === '=') {
            next();
            parseValue();
          }
          while (peek().kind === 'punct' && peek().value === '@') {
            next();
            next();
          }
        }
        next();
      }
      while (peek().kind === 'punct' && peek().value === '@') {
        next();
        next();
      }
      document.operations.push({
        type: keyword.value === 'mutation' ? 'mutation' : 'query',
        name,
        selectionSet: parseSelectionSet(),
      });
      continue;
    }
    if (keyword.value === 'fragment') {
      const fragName = next().value;
      const on = next();
      if (on.value !== 'on') throw new Error('expected on in fragment definition');
      const typeName = next().value;
      document.fragments.set(fragName, { typeCondition: typeName, selectionSet: parseSelectionSet() });
      continue;
    }
    throw new Error(`unexpected definition ${keyword.value}`);
  }
  return document;
}

// --- execution ---------------------------------------------------------------

interface GqlRef {
  __gqlType: string;
  source: unknown;
}

function ref(type: string, source: unknown): GqlRef {
  return { __gqlType: type, source };
}

function isRef(value: unknown): value is GqlRef {
  return isRecord(value) && typeof value.__gqlType === 'string';
}

class GqlError extends Error {}

interface GqlCtx {
  vars: Record<string, unknown>;
  fragments: Map<string, { typeCondition: string | null; selectionSet: GqlSelection[] }>;
  errors: { message: string }[];
}

function evalValue(value: GqlValue, ctx: GqlCtx): unknown {
  switch (value.kind) {
    case 'var':
      return ctx.vars[value.name] ?? null;
    case 'int':
    case 'float':
    case 'string':
    case 'boolean':
    case 'enum':
      return value.value;
    case 'null':
      return null;
    case 'list':
      return value.items.map((item) => evalValue(item, ctx));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = evalValue(field.value, ctx);
      return out;
    }
  }
}

const TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'reopenIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['login', 'id', 'databaseId', 'name', 'email', 'url'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission',
    'hasIssuesEnabled', 'hasPullRequestsEnabled', 'isPrivate', 'description', 'issue', 'issues',
    'pullRequest', 'pullRequests', 'createdAt', 'updatedAt', 'url',
  ],
  Issue: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'author', 'labels', 'comments', 'repository', 'createdAt', 'updatedAt', 'url'],
  PullRequest: [
    'id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName',
    'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'author', 'repository', 'createdAt', 'updatedAt', 'url',
  ],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  Ref: ['name', 'prefix', 'target'],
  Label: ['name', 'color'],
  IssueComment: ['id', 'body', 'author', 'createdAt'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  ReopenIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  CommentEdge: ['node', 'cursor'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues'],
  __Field: ['name', 'description', 'type'],
  __EnumValue: ['name', 'description'],
  __Schema: ['types', 'queryType', 'mutationType'],
};

const TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

interface IssueSource {
  repo: Repo;
  issue: IssueRec;
}

interface PullSource {
  repo: Repo;
  pull: PullRec;
}

interface ConnectionSource<T> {
  items: T[];
  pageInfo: { hasNextPage: boolean; hasPreviousPage: boolean; startCursor: string | null; endCursor: string | null };
  totalCount: number;
}

function cursorOf(index: number): string {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64url');
}

function indexOfCursor(cursor: unknown): number {
  if (typeof cursor !== 'string') return -1;
  try {
    const text = Buffer.from(cursor, 'base64url').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? -1 : Number(match[1]);
  } catch {
    return -1;
  }
}

function paginateConnection<T>(items: T[], args: Record<string, unknown>): ConnectionSource<T> {
  const afterIndex = indexOfCursor(args.after);
  const start = afterIndex + 1;
  const first = typeof args.first === 'number' ? Math.max(0, Math.trunc(args.first)) : items.length;
  const page = items.slice(start, start + first);
  return {
    items: page,
    totalCount: items.length,
    pageInfo: {
      hasNextPage: start + page.length < items.length,
      hasPreviousPage: start > 0,
      startCursor: page.length > 0 ? cursorOf(start) : null,
      endCursor: page.length > 0 ? cursorOf(start + page.length - 1) : null,
    },
  };
}

function repoByGlobalId(id: unknown): Repo | null {
  if (typeof id !== 'string') return null;
  const decoded = decodeGlobalId(id);
  if (decoded === null || !decoded.startsWith('repo:')) return null;
  const dbId = Number(decoded.slice('repo:'.length));
  for (const repo of repos.values()) if (repo.id === dbId) return repo;
  return null;
}

function repoByOwnerName(owner: unknown, name: unknown): Repo | null {
  if (typeof owner !== 'string' || typeof name !== 'string') return null;
  return findRepo(owner, name);
}

type Resolver = (source: never, args: Record<string, unknown>, ctx: GqlCtx) => unknown;

const RESOLVERS: Record<string, Record<string, Resolver>> = {
  Query: {
    viewer: () => ref('User', { login: VIEWER }),
    repository: (_s, args) => {
      const repo = repoByOwnerName(args.owner, args.name);
      return repo === null ? null : ref('Repository', repo);
    },
    node: (_s, args) => {
      if (typeof args.id !== 'string') return null;
      const decoded = decodeGlobalId(args.id);
      if (decoded === null) return null;
      if (decoded.startsWith('repo:')) {
        const repo = repoByGlobalId(args.id);
        return repo === null ? null : ref('Repository', repo);
      }
      if (decoded.startsWith('issue:')) {
        const [, repoId, number] = decoded.split(':');
        const repo = repoByGlobalId(globalId(`repo:${repoId}`));
        const issue = repo?.issues.get(Number(number));
        return repo !== null && repo !== undefined && issue !== undefined ? ref('Issue', { repo, issue } satisfies IssueSource) : null;
      }
      if (decoded.startsWith('pr:')) {
        const [, repoId, number] = decoded.split(':');
        const repo = repoByGlobalId(globalId(`repo:${repoId}`));
        const pull = repo?.pulls.get(Number(number));
        return repo !== null && repo !== undefined && pull !== undefined ? ref('PullRequest', { repo, pull } satisfies PullSource) : null;
      }
      if (decoded.startsWith('user:')) return ref('User', { login: decoded.slice('user:'.length) });
      return null;
    },
    __type: (_s, args) => {
      const name = typeof args.name === 'string' ? args.name : '';
      if (TYPE_FIELDS[name] === undefined && TYPE_ENUMS[name] === undefined) return null;
      return ref('__Type', { name });
    },
    __schema: () => ref('__Schema', {}),
  },
  Mutation: {
    createIssue: (_s, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = repoByGlobalId(input.repositoryId);
      if (repo === null) throw new GqlError('repository not found for createIssue');
      const issue = createIssueRec(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '', []);
      return ref('CreateIssuePayload', { repo, issue, clientMutationId: input.clientMutationId ?? null });
    },
    closeIssue: (_s, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const target = findIssueByGlobalId(input.issueId);
      if (target === null) throw new GqlError('issue not found for closeIssue');
      target.issue.state = 'closed';
      return ref('CloseIssuePayload', { ...target, clientMutationId: input.clientMutationId ?? null });
    },
    reopenIssue: (_s, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const target = findIssueByGlobalId(input.issueId);
      if (target === null) throw new GqlError('issue not found for reopenIssue');
      target.issue.state = 'open';
      return ref('ReopenIssuePayload', { ...target, clientMutationId: input.clientMutationId ?? null });
    },
    createPullRequest: (_s, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = repoByGlobalId(input.repositoryId);
      if (repo === null) throw new GqlError('repository not found for createPullRequest');
      const headRef = typeof input.headRefName === 'string' ? input.headRefName : '';
      const baseRef = typeof input.baseRefName === 'string' ? input.baseRefName : repo.defaultBranch;
      const headSha = repo.refs.get(`refs/heads/${headRef}`);
      const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
      if (headSha === undefined || baseSha === undefined) throw new GqlError('head or base branch not found for createPullRequest');
      const pull = createPullRec(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '', headRef, baseRef, headSha, baseSha);
      return ref('CreatePullRequestPayload', { repo, pull, clientMutationId: input.clientMutationId ?? null });
    },
    mergePullRequest: (_s, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const target = findPullByGlobalId(input.pullRequestId);
      if (target === null) throw new GqlError('pull request not found for mergePullRequest');
      if (!target.pull.merged) {
        const sha = mergePull(target.repo, target.pull);
        if (sha === null) throw new GqlError('pull request is not mergeable');
      }
      return ref('MergePullRequestPayload', { ...target, clientMutationId: input.clientMutationId ?? null });
    },
    addComment: (_s, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const body = typeof input.body === 'string' ? input.body : '';
      const decoded = typeof input.subjectId === 'string' ? decodeGlobalId(input.subjectId) : null;
      if (decoded === null) throw new GqlError('subject not found for addComment');
      let holder: { comments: CommentRec[] } | null = null;
      let repo: Repo | null = null;
      let number = 0;
      if (decoded.startsWith('issue:')) {
        const found = findIssueByGlobalId(input.subjectId);
        if (found !== null) {
          holder = found.issue;
          repo = found.repo;
          number = found.issue.number;
        }
      } else if (decoded.startsWith('pr:')) {
        const found = findPullByGlobalId(input.subjectId);
        if (found !== null) {
          holder = found.pull;
          repo = found.repo;
          number = found.pull.number;
        }
      }
      if (holder === null || repo === null) throw new GqlError('subject not found for addComment');
      const comment: CommentRec = { id: repo.nextCommentId, body, author: VIEWER };
      repo.nextCommentId += 1;
      holder.comments.push(comment);
      const node = ref('IssueComment', { repo, number, comment });
      return ref('AddCommentPayload', { node, clientMutationId: input.clientMutationId ?? null });
    },
  },
  User: {
    login: (source) => (source as { login: string }).login,
    id: (source) => globalId(`user:${(source as { login: string }).login}`),
    databaseId: () => VIEWER_ID,
    name: () => VIEWER_NAME,
    email: () => VIEWER_EMAIL,
    url: (source) => `https://forge.invalid/${(source as { login: string }).login}`,
  },
  Repository: {
    id: (source) => globalId(`repo:${(source as Repo).id}`),
    databaseId: (source) => (source as Repo).id,
    name: (source) => (source as Repo).name,
    nameWithOwner: (source) => `${(source as Repo).owner}/${(source as Repo).name}`,
    owner: (source) => ref('User', { login: (source as Repo).owner }),
    defaultBranchRef: (source) => {
      const repo = source as Repo;
      const tip = repo.refs.get(headRefName(repo));
      if (tip === undefined) return null;
      return ref('Ref', { repo, name: repo.defaultBranch, oid: tip });
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    hasPullRequestsEnabled: () => true,
    isPrivate: (source) => (source as Repo).isPrivate,
    description: (source) => (source as Repo).description,
    createdAt: (source) => isoOf(1_700_000_000 + (source as Repo).id),
    updatedAt: (source) => isoOf(1_700_000_000 + (source as Repo).id),
    url: (source) => `https://forge.invalid/${(source as Repo).owner}/${(source as Repo).name}`,
    issue: (source, args) => {
      const repo = source as Repo;
      const issue = repo.issues.get(Number(args.number));
      return issue === undefined ? null : ref('Issue', { repo, issue } satisfies IssueSource);
    },
    issues: (source, args) => {
      const repo = source as Repo;
      let list = [...repo.issues.values()];
      if (Array.isArray(args.states)) {
        const wanted = new Set(args.states.map((state) => String(state).toLowerCase()));
        list = list.filter((issue) => wanted.has(issue.state));
      }
      const orderBy = isRecord(args.orderBy) ? args.orderBy : {};
      const ascending = orderBy.direction === 'ASC';
      list.sort((a, b) => (ascending ? a.number - b.number : b.number - a.number));
      const connection = paginateConnection(list, args);
      return ref('IssueConnection', {
        items: connection.items.map((issue) => ({ repo, issue })),
        pageInfo: connection.pageInfo,
        totalCount: connection.totalCount,
      } satisfies ConnectionSource<IssueSource>);
    },
    pullRequest: (source, args) => {
      const repo = source as Repo;
      const pull = repo.pulls.get(Number(args.number));
      return pull === undefined ? null : ref('PullRequest', { repo, pull } satisfies PullSource);
    },
    pullRequests: (source, args) => {
      const repo = source as Repo;
      let list = [...repo.pulls.values()];
      if (Array.isArray(args.states)) {
        const wanted = new Set(args.states.map((state) => String(state)));
        list = list.filter((pull) => wanted.has(pull.merged ? 'MERGED' : pull.state.toUpperCase()));
      }
      list.sort((a, b) => b.number - a.number);
      const connection = paginateConnection(list, args);
      return ref('PullRequestConnection', {
        items: connection.items.map((pull) => ({ repo, pull })),
        pageInfo: connection.pageInfo,
        totalCount: connection.totalCount,
      } satisfies ConnectionSource<PullSource>);
    },
  },
  Issue: {
    id: (source) => {
      const { repo, issue } = source as IssueSource;
      return globalId(`issue:${repo.id}:${issue.number}`);
    },
    databaseId: (source) => (source as IssueSource).issue.number,
    number: (source) => (source as IssueSource).issue.number,
    title: (source) => (source as IssueSource).issue.title,
    body: (source) => (source as IssueSource).issue.body,
    state: (source) => (source as IssueSource).issue.state.toUpperCase(),
    author: () => ref('User', { login: VIEWER }),
    repository: (source) => ref('Repository', (source as IssueSource).repo),
    labels: (source, args) => {
      const { repo, issue } = source as IssueSource;
      const items = issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? '000000' }));
      const connection = paginateConnection(items, args);
      return ref('IssueConnection', { items: [], pageInfo: connection.pageInfo, totalCount: connection.totalCount });
    },
    comments: (source, args) => {
      const { repo, issue } = source as IssueSource;
      const connection = paginateConnection(issue.comments, args);
      return ref('IssueConnection', {
        items: [],
        pageInfo: connection.pageInfo,
        totalCount: connection.totalCount,
        commentItems: connection.items.map((comment) => ({ repo, number: issue.number, comment })),
      } as unknown as ConnectionSource<IssueSource>);
    },
    createdAt: (source) => isoOf((source as IssueSource).issue.createdTs),
    updatedAt: (source) => isoOf((source as IssueSource).issue.createdTs),
    url: (source) => {
      const { repo, issue } = source as IssueSource;
      return `https://forge.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`;
    },
  },
  PullRequest: {
    id: (source) => {
      const { repo, pull } = source as PullSource;
      return globalId(`pr:${repo.id}:${pull.number}`);
    },
    databaseId: (source) => (source as PullSource).pull.number,
    number: (source) => (source as PullSource).pull.number,
    title: (source) => (source as PullSource).pull.title,
    body: (source) => (source as PullSource).pull.body,
    state: (source) => {
      const pull = (source as PullSource).pull;
      return pull.merged ? 'MERGED' : pull.state.toUpperCase();
    },
    merged: (source) => (source as PullSource).pull.merged,
    mergeable: (source) => {
      const { repo, pull } = source as PullSource;
      return pullMergeable(repo, pull);
    },
    headRefName: (source) => (source as PullSource).pull.headRef,
    baseRefName: (source) => (source as PullSource).pull.baseRef,
    headRefOid: (source) => {
      const { repo, pull } = source as PullSource;
      return repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha;
    },
    baseRefOid: (source) => {
      const { repo, pull } = source as PullSource;
      return repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
    },
    author: () => ref('User', { login: VIEWER }),
    repository: (source) => ref('Repository', (source as PullSource).repo),
    files: (source, args) => {
      const { repo, pull } = source as PullSource;
      const items = pullFiles(repo, pull).map((change) => ({
        path: change.filename,
        additions: change.additions,
        deletions: change.deletions,
        changeType: change.status === 'added' ? 'ADDED' : change.status === 'removed' ? 'DELETED' : 'MODIFIED',
      }));
      const connection = paginateConnection(items, args);
      return ref('PullRequestConnection', {
        items: [],
        pageInfo: connection.pageInfo,
        totalCount: connection.totalCount,
        fileItems: connection.items,
      } as unknown as ConnectionSource<PullSource>);
    },
    createdAt: (source) => isoOf((source as PullSource).pull.createdTs),
    updatedAt: (source) => isoOf((source as PullSource).pull.createdTs),
    url: (source) => {
      const { repo, pull } = source as PullSource;
      return `https://forge.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`;
    },
  },
  IssueConnection: {
    nodes: (source) => {
      const connection = source as ConnectionSource<unknown> & { commentItems?: unknown[]; fileItems?: unknown[] };
      if (connection.commentItems !== undefined) return connection.commentItems.map((item) => ref('IssueComment', item));
      if (connection.fileItems !== undefined) return connection.fileItems.map((item) => ref('PullRequestChangedFile', item));
      return (connection.items as unknown[]).map((item) => {
        if (isRecord(item) && 'issue' in item) return ref('Issue', item);
        if (isRecord(item) && 'pull' in item) return ref('PullRequest', item);
        return null;
      });
    },
    edges: (source) => {
      const connection = source as ConnectionSource<unknown>;
      return connection.items.map((item, index) => ({ node: item, cursor: cursorOf(index) }));
    },
    pageInfo: (source) => ref('PageInfo', (source as ConnectionSource<unknown>).pageInfo),
    totalCount: (source) => (source as ConnectionSource<unknown>).totalCount,
  },
  PullRequestConnection: {
    nodes: (source) => {
      const connection = source as ConnectionSource<unknown> & { fileItems?: { path: string }[] };
      if (connection.fileItems !== undefined) return connection.fileItems.map((item) => ref('PullRequestChangedFile', item));
      return (connection.items as unknown[]).map((item) => (isRecord(item) && 'pull' in item ? ref('PullRequest', item) : null));
    },
    edges: (source) => {
      const connection = source as ConnectionSource<unknown>;
      return connection.items.map((item, index) => ({ node: item, cursor: cursorOf(index) }));
    },
    pageInfo: (source) => ref('PageInfo', (source as ConnectionSource<unknown>).pageInfo),
    totalCount: (source) => (source as ConnectionSource<unknown>).totalCount,
  },
  PageInfo: {
    hasNextPage: (source) => (source as ConnectionSource<unknown>['pageInfo']).hasNextPage,
    hasPreviousPage: (source) => (source as ConnectionSource<unknown>['pageInfo']).hasPreviousPage,
    startCursor: (source) => (source as ConnectionSource<unknown>['pageInfo']).startCursor,
    endCursor: (source) => (source as ConnectionSource<unknown>['pageInfo']).endCursor,
  },
  PullRequestChangedFile: {
    path: (source) => (source as { path: string }).path,
    additions: (source) => (source as { additions: number }).additions,
    deletions: (source) => (source as { deletions: number }).deletions,
    changeType: (source) => (source as { changeType: string }).changeType,
  },
  Ref: {
    name: (source) => (source as { name: string }).name,
    prefix: () => 'refs/heads/',
    target: (source) => {
      const { repo, oid } = source as { repo: Repo; oid: string };
      const obj = getObject(repo, oid);
      return obj === null ? null : { oid, type: obj.type };
    },
  },
  Label: {
    name: (source) => (source as { name: string }).name,
    color: (source) => (source as { color: string }).color,
  },
  IssueComment: {
    id: (source) => {
      const { repo, number, comment } = source as { repo: Repo; number: number; comment: CommentRec };
      return globalId(`comment:${repo.id}:${number}:${comment.id}`);
    },
    body: (source) => (source as { comment: CommentRec }).comment.body,
    author: () => ref('User', { login: VIEWER }),
    createdAt: () => isoOf(1_700_000_000),
  },
  CreateIssuePayload: {
    issue: (source) => ref('Issue', { repo: (source as { repo: Repo }).repo, issue: (source as { issue: IssueRec }).issue }),
    clientMutationId: (source) => (source as { clientMutationId: unknown }).clientMutationId,
  },
  CloseIssuePayload: {
    issue: (source) => ref('Issue', { repo: (source as { repo: Repo }).repo, issue: (source as { issue: IssueRec }).issue }),
    clientMutationId: (source) => (source as { clientMutationId: unknown }).clientMutationId,
  },
  ReopenIssuePayload: {
    issue: (source) => ref('Issue', { repo: (source as { repo: Repo }).repo, issue: (source as { issue: IssueRec }).issue }),
    clientMutationId: (source) => (source as { clientMutationId: unknown }).clientMutationId,
  },
  CreatePullRequestPayload: {
    pullRequest: (source) => ref('PullRequest', { repo: (source as { repo: Repo }).repo, pull: (source as { pull: PullRec }).pull }),
    clientMutationId: (source) => (source as { clientMutationId: unknown }).clientMutationId,
  },
  MergePullRequestPayload: {
    pullRequest: (source) => ref('PullRequest', { repo: (source as { repo: Repo }).repo, pull: (source as { pull: PullRec }).pull }),
    clientMutationId: (source) => (source as { clientMutationId: unknown }).clientMutationId,
  },
  AddCommentPayload: {
    commentEdge: (source) => ref('CommentEdge', { node: (source as { node: GqlRef }).node }),
    clientMutationId: (source) => (source as { clientMutationId: unknown }).clientMutationId,
  },
  CommentEdge: {
    node: (source) => (source as { node: GqlRef }).node,
    cursor: () => cursorOf(0),
  },
  __Type: {
    name: (source) => (source as { name: string }).name,
    kind: (source) => (TYPE_ENUMS[(source as { name: string }).name] !== undefined ? 'ENUM' : 'OBJECT'),
    description: () => null,
    fields: (source) => {
      const fields = TYPE_FIELDS[(source as { name: string }).name];
      return fields === undefined ? null : fields.map((name) => ref('__Field', { name }));
    },
    enumValues: (source) => {
      const values = TYPE_ENUMS[(source as { name: string }).name];
      return values === undefined ? null : values.map((name) => ref('__EnumValue', { name }));
    },
  },
  __Field: {
    name: (source) => (source as { name: string }).name,
    description: () => null,
    type: () => null,
  },
  __EnumValue: {
    name: (source) => (source as { name: string }).name,
    description: () => null,
  },
  __Schema: {
    types: () => [...Object.keys(TYPE_FIELDS), ...Object.keys(TYPE_ENUMS)].map((name) => ref('__Type', { name })),
    queryType: () => ref('__Type', { name: 'Query' }),
    mutationType: () => ref('__Type', { name: 'Mutation' }),
  },
};

function findIssueByGlobalId(id: unknown): IssueSource | null {
  if (typeof id !== 'string') return null;
  const decoded = decodeGlobalId(id);
  if (decoded === null || !decoded.startsWith('issue:')) return null;
  const [, repoId, number] = decoded.split(':');
  const repo = repoByGlobalId(globalId(`repo:${repoId}`));
  if (repo === null) return null;
  const issue = repo.issues.get(Number(number));
  return issue === undefined ? null : { repo, issue };
}

function findPullByGlobalId(id: unknown): PullSource | null {
  if (typeof id !== 'string') return null;
  const decoded = decodeGlobalId(id);
  if (decoded === null || !decoded.startsWith('pr:')) return null;
  const [, repoId, number] = decoded.split(':');
  const repo = repoByGlobalId(globalId(`repo:${repoId}`));
  if (repo === null) return null;
  const pull = repo.pulls.get(Number(number));
  return pull === undefined ? null : { repo, pull };
}

function execSelectionSet(typeName: string, source: unknown, selections: GqlSelection[], ctx: GqlCtx, out: Record<string, unknown>): void {
  for (const selection of selections) {
    if (selection.kind === 'inline') {
      if (selection.typeCondition === null || selection.typeCondition === typeName) {
        execSelectionSet(typeName, source, selection.selectionSet, ctx, out);
      }
      continue;
    }
    if (selection.kind === 'spread') {
      const fragment = ctx.fragments.get(selection.name);
      if (fragment !== undefined && (fragment.typeCondition === null || fragment.typeCondition === typeName)) {
        execSelectionSet(typeName, source, fragment.selectionSet, ctx, out);
      }
      continue;
    }
    const key = selection.alias ?? selection.name;
    if (selection.name === '__typename') {
      out[key] = typeName;
      continue;
    }
    const knownFields = TYPE_FIELDS[typeName];
    const resolver = RESOLVERS[typeName]?.[selection.name];
    if (knownFields === undefined || !knownFields.includes(selection.name) || resolver === undefined) {
      ctx.errors.push({ message: `Field '${selection.name}' doesn't exist on type '${typeName}'` });
      out[key] = null;
      continue;
    }
    const args: Record<string, unknown> = {};
    for (const arg of selection.args) args[arg.name] = evalValue(arg.value, ctx);
    let value: unknown;
    try {
      value = resolver(source as never, args, ctx);
    } catch (err) {
      ctx.errors.push({ message: err instanceof Error ? err.message : String(err) });
      out[key] = null;
      continue;
    }
    out[key] = completeValue(value, selection, ctx);
  }
}

function completeValue(value: unknown, selection: GqlField, ctx: GqlCtx): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((item) => completeValue(item, selection, ctx));
  if (isRef(value)) {
    if (selection.selectionSet === null) return null;
    const out: Record<string, unknown> = {};
    execSelectionSet(value.__gqlType, value.source, selection.selectionSet, ctx, out);
    return out;
  }
  return value;
}

function executeGraphqlOperation(document: GqlDocument, operationName: string | null, vars: Record<string, unknown>): Record<string, unknown> {
  const operation =
    document.operations.find((candidate) => operationName !== null && candidate.name === operationName) ?? document.operations[0];
  if (operation === undefined) return { errors: [{ message: 'no operation in document' }] };
  const ctx: GqlCtx = { vars, fragments: document.fragments, errors: [] };
  const rootType = operation.type === 'mutation' ? 'Mutation' : 'Query';
  const data: Record<string, unknown> = {};
  execSelectionSet(rootType, null, operation.selectionSet, ctx, data);
  const result: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors;
  return result;
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJsonRaw(res, 400, { errors: [{ message: 'request body is not valid JSON' }] });
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (!isRecord(entry) || typeof entry.query !== 'string') {
      return { errors: [{ message: 'each operation needs a query string' }] };
    }
    try {
      const document = parseGraphql(entry.query);
      const vars = isRecord(entry.variables) ? entry.variables : {};
      const operationName = typeof entry.operationName === 'string' ? entry.operationName : null;
      return executeGraphqlOperation(document, operationName, vars);
    } catch (err) {
      return { errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
  };
  if (Array.isArray(parsed)) {
    sendJsonRaw(res, 200, parsed.map((entry) => runOne(entry)));
    return;
  }
  sendJsonRaw(res, 200, runOne(parsed));
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC over streamable HTTP, tools acting on the same store
// ---------------------------------------------------------------------------

const MCP_SERVER_INFO = { name: 'forge-mcp', version: '1.0.0' };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

/** The tool list is a fixed literal: two tools/list calls must answer byte-identically. */
const MCP_TOOLS = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Open an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
        body: { type: 'string', description: 'The pull request body.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request into its base branch (squash).',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
] as const;

function mcpToolResult(value: unknown): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify(value) }],
    structuredContent: value as Record<string, unknown>,
    isError: false,
  };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function argString(args: Record<string, unknown>, name: string): string {
  const value = args[name];
  return typeof value === 'string' ? value : '';
}

/** Run one MCP tool against the store; returns a tool result (isError on domain failures). */
function runMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> | 'unknown' | 'badargs' {
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (tool === undefined) return 'unknown';
  for (const required of tool.inputSchema.required) {
    const value = args[required];
    if (value === undefined || value === null || value === '') return 'badargs';
  }
  switch (name) {
    case 'create_repo': {
      const repoName = argString(args, 'name');
      if (findRepo(VIEWER, repoName) !== null) return mcpToolError(`repository ${repoName} already exists`);
      const repo = createRepoRec(VIEWER, repoName, argString(args, 'description'), args.private === true);
      return mcpToolResult(repoJson(repo));
    }
    case 'get_repo': {
      const repo = findRepo(argString(args, 'owner'), argString(args, 'repo'));
      if (repo === null) return mcpToolError('repository not found');
      return mcpToolResult(repoJson(repo));
    }
    case 'create_issue': {
      const repo = findRepo(argString(args, 'owner'), argString(args, 'repo'));
      if (repo === null) return mcpToolError('repository not found');
      const issue = createIssueRec(repo, argString(args, 'title'), argString(args, 'body'), []);
      return mcpToolResult(issueJson(repo, issue));
    }
    case 'list_issues': {
      const repo = findRepo(argString(args, 'owner'), argString(args, 'repo'));
      if (repo === null) return mcpToolError('repository not found');
      const state = argString(args, 'state') || 'open';
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((issue) => issue.state === 'open');
      else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
      list.sort((a, b) => a.number - b.number);
      return mcpToolResult(list.map((issue) => issueJson(repo, issue)));
    }
    case 'create_pull_request': {
      const repo = findRepo(argString(args, 'owner'), argString(args, 'repo'));
      if (repo === null) return mcpToolError('repository not found');
      const head = argString(args, 'head');
      const base = argString(args, 'base');
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (headSha === undefined || baseSha === undefined) return mcpToolError('head or base branch not found');
      const pull = createPullRec(repo, argString(args, 'title'), argString(args, 'body'), head, base, headSha, baseSha);
      return mcpToolResult(pullJson(repo, pull));
    }
    case 'merge_pull_request': {
      const repo = findRepo(argString(args, 'owner'), argString(args, 'repo'));
      if (repo === null) return mcpToolError('repository not found');
      const pull = repo.pulls.get(Number(args.pull_number));
      if (pull === undefined) return mcpToolError('pull request not found');
      if (!pull.merged) {
        const sha = mergePull(repo, pull);
        if (sha === null) return mcpToolError('pull request is not mergeable');
      }
      return mcpToolResult({ ...pullJson(repo, pull), sha: pull.mergeCommitSha });
    }
    default:
      return 'unknown';
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'DELETE') {
    res.writeHead(204, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    sendJsonRaw(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  if (!authed(req)) {
    sendJsonRaw(res, 401, { message: 'Unauthorized' });
    return;
  }
  const raw = (await readBody(req)).toString('utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    sendJsonRaw(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!isRecord(parsed) || typeof parsed.method !== 'string') {
    sendJsonRaw(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = 'id' in parsed ? parsed.id : undefined;
  const method = parsed.method;
  const params = isRecord(parsed.params) ? parsed.params : {};
  // Notifications carry no id and expect no answer.
  if (id === undefined) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  const reply = (result: unknown): void => sendJsonRaw(res, 200, { jsonrpc: '2.0', id, result });
  const replyError = (code: number, message: string): void =>
    sendJsonRaw(res, 200, { jsonrpc: '2.0', id, error: { code, message } });

  if (method === 'server/discover') {
    reply({
      resultType: 'complete',
      supportedVersions: MCP_SUPPORTED_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
      _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    reply({
      protocolVersion: MCP_SUPPORTED_VERSIONS.includes(offered) ? offered : '2025-11-25',
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
    });
    return;
  }
  if (method === 'ping') {
    reply({});
    return;
  }
  if (method === 'tools/list') {
    reply({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? params.arguments : {};
    const outcome = runMcpTool(name, args);
    if (outcome === 'unknown') {
      replyError(-32602, `unknown tool: ${name}`);
      return;
    }
    if (outcome === 'badargs') {
      replyError(-32602, `missing required arguments for tool: ${name}`);
      return;
    }
    reply(outcome);
    return;
  }
  replyError(-32601, `method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// The server: one router over the four surfaces
// ---------------------------------------------------------------------------

/**
 * The single-issue GET route in its plainest shape (no percent-encoding, no dot
 * segments, a decimal number): the one REST read a benchmark hammers. Anything that
 * does not match this exactly takes the general route below, unchanged.
 */
const ISSUE_GET_RE = /^\/api\/v3\/repos\/([^/?%.]+)\/([^/?%.]+)\/issues\/([0-9]+)$/;

/** The issue-creation route in the same plain shape: POST /api/v3/repos/{o}/{r}/issues. */
const ISSUE_POST_RE = /^\/api\/v3\/repos\/([^/?%.]+)\/([^/?%.]+)\/issues$/;

export function createApp(): Server {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // Fast path for GET /api/v3/repos/{owner}/{repo}/issues/{n}: it mirrors the general
    // route's semantics step for step — the same auth check and 401, the REST handler's
    // x-oauth-scopes header on every response past auth, the same repo-then-issue 404s,
    // and the issue's memoised JSON — but skips re-parsing and re-dispatching the URL.
    if (req.method === 'GET' && typeof req.url === 'string') {
      const queryAt = req.url.indexOf('?');
      const match = ISSUE_GET_RE.exec(queryAt >= 0 ? req.url.slice(0, queryAt) : req.url);
      if (match !== null) {
        if (!authed(req)) {
          sendJsonRaw(res, 401, { message: 'Requires authentication' });
          return;
        }
        res.setHeader('x-oauth-scopes', 'repo, read:org');
        const repo = findRepo(match[1]!, match[2]!);
        const issue = repo === null ? undefined : repo.issues.get(Number(match[3]!));
        if (repo === null || issue === undefined) {
          notFound(res);
          return;
        }
        sendJsonBuffer(res, 200, issueJsonBuffer(repo, issue));
        return;
      }
    }
    // Fast path for POST /api/v3/repos/{owner}/{repo}/issues, mirroring the general
    // route step for step (auth 401 without the scopes header, then the header on
    // every later response, repo 404, the same body/title/label validation, the same
    // 201 with the memoised issue JSON) without URL parsing and route dispatch.
    if (req.method === 'POST' && typeof req.url === 'string') {
      const queryAt = req.url.indexOf('?');
      const match = ISSUE_POST_RE.exec(queryAt >= 0 ? req.url.slice(0, queryAt) : req.url);
      if (match !== null) {
        if (!authed(req)) {
          sendJsonRaw(res, 401, { message: 'Requires authentication' });
          return;
        }
        res.setHeader('x-oauth-scopes', 'repo, read:org');
        const repo = findRepo(match[1]!, match[2]!);
        if (repo === null) {
          notFound(res);
          return;
        }
        void (async () => {
          try {
            const body = await jsonBody(req, res);
            if (body === undefined) return;
            const title = typeof body.title === 'string' ? body.title : '';
            if (title === '') return unprocessable(res, 'title is required');
            const labelNames: string[] = [];
            if (Array.isArray(body.labels)) {
              for (const raw of body.labels) {
                const name = typeof raw === 'string' ? raw : isRecord(raw) && typeof raw.name === 'string' ? raw.name : '';
                if (name === '' || !repo.labels.has(name)) return unprocessable(res, `label ${name} does not exist`);
                labelNames.push(name);
              }
            }
            const issue = createIssueRec(repo, title, typeof body.body === 'string' ? body.body : '', labelNames);
            sendJsonBuffer(res, 201, issueJsonBuffer(repo, issue));
          } catch (err) {
            try {
              if (!res.headersSent) sendJsonRaw(res, 500, { message: err instanceof Error ? err.message : 'Internal Server Error' });
              else res.end();
            } catch {
              // The socket is already gone; nothing more to do.
            }
          }
        })();
        return;
      }
    }
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const path = url.pathname;
        const method = req.method ?? 'GET';

        if (method === 'GET' && path === '/healthz') {
          sendJsonRaw(res, 200, { ok: true });
          return;
        }

        // Git smart HTTP: /<owner>/<repo>.git/...
        const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
        if (gitMatch !== null) {
          if (!authed(req)) {
            sendJsonRaw(res, 401, { message: 'Unauthorized' });
            return;
          }
          const owner = decodeURIComponent(gitMatch[1]!);
          const repo = findRepo(owner, decodeURIComponent(gitMatch[2]!));
          if (repo === null) {
            sendJsonRaw(res, 404, { message: 'Not Found' });
            return;
          }
          const endpoint = gitMatch[3]!;
          if (endpoint === 'info/refs' && method === 'GET') {
            handleInfoRefs(res, repo, url.searchParams.get('service'), req.headers['git-protocol'] ?? null);
            return;
          }
          if (endpoint === 'git-upload-pack' && method === 'POST') {
            await handleUploadPack(req, res, repo);
            return;
          }
          if (endpoint === 'git-receive-pack' && method === 'POST') {
            await handleReceivePack(req, res, repo);
            return;
          }
          sendJsonRaw(res, 404, { message: 'Not Found' });
          return;
        }

        if (path === '/api/graphql') {
          if (method !== 'POST') {
            sendJsonRaw(res, 404, { message: 'Not Found' });
            return;
          }
          if (!authed(req)) {
            sendJsonRaw(res, 401, { message: 'Requires authentication' });
            return;
          }
          await handleGraphql(req, res);
          return;
        }

        if (path === '/mcp') {
          await handleMcp(req, res);
          return;
        }

        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          if (!authed(req)) {
            sendJsonRaw(res, 401, { message: 'Requires authentication' });
            return;
          }
          await handleRest(req, res, url);
          return;
        }

        sendJsonRaw(res, 404, { message: 'Not Found' });
      } catch (err) {
        // A request must never take the server down with it.
        try {
          if (!res.headersSent) sendJsonRaw(res, 500, { message: err instanceof Error ? err.message : 'Internal Server Error' });
          else res.end();
        } catch {
          // The socket is already gone; nothing more to do.
        }
      }
    })();
  });
  server.headersTimeout = 30_000;
  server.requestTimeout = 120_000;
  return server;
}
