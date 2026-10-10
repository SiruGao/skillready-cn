#!/usr/bin/env node
import { lstat, opendir, readFile, writeFile, mkdir, realpath } from 'node:fs/promises';
import { resolve, relative, dirname, extname, basename, sep } from 'node:path';
import { webcrypto } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { analyzeFiles, LIMITS, SUPPORTED_EXTENSIONS } from './dist/engine.js';

if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', '.hg', '.svn', '.venv', 'venv']);
const HELP = `SkillReady — 中文团队 AI Skill 接入静态验收单

用法：node cli.mjs <文件或目录...> [--json <输出文件>] [--fail-on high|medium|none]

  --json <路径>          保存已脱敏 JSON 报告
  --fail-on <级别>       high：高风险命中退出 1（默认）
                        medium：中高风险命中退出 1；none：只生成报告
  --allow-domain <域名>  添加允许域名，可重复；包含子域，只影响域名提示级别
  --help                显示帮助

退出码：0 完成且未达到阈值，1 达到风险阈值，2 输入或运行错误。
上限：100 个文件，单文件 1 MB，总计 5 MB，目录深度 12，遍历条目 2000。
默认不跟随符号链接；跳过 .git、node_modules、dist、虚拟环境与二进制。
全程静态分析，不执行被检文本、不联网；无命中不代表安全认证。`;

export async function run(argv, io = { out: console.log, err: console.error }) {
  try {
    const paths = [];
    const allowedDomains = [];
    let jsonPath;
    let failOn = 'high';
    let literalPaths = false;
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      if (literalPaths) { paths.push(arg); continue; }
      if (arg === '--') { literalPaths = true; continue; }
      if (arg === '--help' || arg === '-h') { io.out(HELP); return 0; }
      if (['--json', '--fail-on', '--allow-domain'].includes(arg)) {
        const next = argv[++i];
        if (!next || next.startsWith('--')) throw new Error(`${arg} 缺少参数。`);
        if (arg === '--json') jsonPath = resolve(next);
        if (arg === '--fail-on') failOn = next;
        if (arg === '--allow-domain') allowedDomains.push(next);
      } else if (arg.startsWith('-')) throw new Error(`未知选项：${arg}。使用 --help 查看用法。`);
      else paths.push(arg);
    }
    if (!['high', 'medium', 'none'].includes(failOn)) throw new Error('--fail-on 只能是 high、medium 或 none。');
    if (!paths.length) throw new Error('请提供至少一个文件或目录。使用 --help 查看用法。');

    const files = [];
    const visited = new Set();
    const inputCanonicalPaths = new Set();
    const skips = { symlink: 0, binary: 0, extension: 0, directory: 0 };
    let totalBytes = 0;
    let entries = 0;
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    async function walk(path, depth = 0) {
      if (++entries > 2000) throw new Error('遍历条目超过 2000，请缩小目录范围。');
      if (depth > 12) throw new Error('目录层级超过 12，请直接指定更小的子目录。');
      const stat = await lstat(path);
      if (stat.isSymbolicLink()) { skips.symlink++; return; }
      const canonical = await realpath(path);
      if (visited.has(canonical)) return;
      visited.add(canonical);
      if (stat.isDirectory()) {
        if (SKIP_DIRS.has(basename(path))) { skips.directory++; return; }
        const children = [];
        for await (const child of await opendir(path)) {
          children.push(child);
          if (children.length + entries > 2000) throw new Error('遍历条目超过 2000，请缩小目录范围。');
        }
        children.sort((a, b) => a.name.localeCompare(b.name));
        for (const child of children) await walk(resolve(path, child.name), depth + 1);
        return;
      }
      if (!stat.isFile()) { skips.binary++; return; }
      if (!SUPPORTED_EXTENSIONS.includes(extname(path).toLowerCase())) { skips.extension++; return; }
      if (jsonPath === path) return; // Avoid re-scanning an existing report as source.
      if (stat.size > LIMITS.maxFileBytes) throw new Error(`单个文件不能超过 1 MB：${path}`);
      const bytes = await readFile(path);
      let content;
      try {
        if (bytes.includes(0)) { skips.binary++; return; }
        content = decoder.decode(bytes);
      } catch { skips.binary++; return; }
      totalBytes += bytes.length;
      if (totalBytes > LIMITS.maxTotalBytes) throw new Error('文件总大小不能超过 5 MB。');
      if (files.length >= LIMITS.maxFiles) throw new Error('最多分析 100 个文件，请缩小目录范围。');
      let name = relative(process.cwd(), path).split(sep).join('/');
      if (!name) name = basename(path);
      inputCanonicalPaths.add(canonical);
      files.push({ name, content });
    }
    for (const path of paths) {
      const absolute = resolve(path);
      if (absolute === jsonPath) throw new Error('JSON 输出路径不能与显式输入文件相同。');
      await walk(absolute);
    }
    if (!files.length) throw new Error('没有找到支持的 UTF-8 文本文件；符号链接和二进制会被跳过。');
    const report = await analyzeFiles(files, { allowedDomains });
    if (Object.values(skips).some(Boolean)) report.coverage.limitations.push(`CLI 已跳过：符号链接 ${skips.symlink}，二进制或非 UTF-8 ${skips.binary}，不支持格式 ${skips.extension}，排除目录 ${skips.directory}。`);
    if (jsonPath) {
      // Existing symlinks are rejected so output cannot silently replace an unrelated file.
      let outputStat;
      try { outputStat = await lstat(jsonPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (outputStat?.isSymbolicLink()) throw new Error('JSON 输出路径不能是符号链接。');
      if (outputStat && inputCanonicalPaths.has(await realpath(jsonPath))) throw new Error('JSON 输出不能覆盖输入文件。');
      await mkdir(dirname(jsonPath), { recursive: true });
      await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    }
    io.out(`SkillReady：已分析 ${report.coverage.scannedFiles} 个文件、${report.summary.skillCount} 个 Skill。`);
    io.out(`高 ${report.summary.high} · 中 ${report.summary.medium} · 信息 ${report.summary.info}；合计 ${report.summary.total} 条线索。`);
    if (jsonPath) io.out(`JSON 报告：${jsonPath}`);
    else for (const finding of report.findings) io.out(`[${finding.severity}] ${finding.file}:${finding.line} ${finding.title}`);
    io.out('仅静态线索；无命中不代表安全认证。');
    return failOn === 'none' ? 0 : report.summary.high > 0 || (failOn === 'medium' && report.summary.medium > 0) ? 1 : 0;
  } catch (error) {
    io.err(`SkillReady 错误：${error.message}`);
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) process.exitCode = await run(process.argv.slice(2));
