/** SkillReady: deterministic, local-only static review. Never executes supplied content. */
export const LIMITS = Object.freeze({ maxFiles: 100, maxFileBytes: 1024 * 1024, maxTotalBytes: 5 * 1024 * 1024 });
export const SUPPORTED_EXTENSIONS = Object.freeze(['.md', '.json', '.yaml', '.yml', '.toml', '.txt', '.sh', '.py', '.js', '.ts']);

const encoder = new TextEncoder();
const SECRET_KEY = '\\b(?:[A-Za-z0-9_]{0,80}(?:api[_-]?key|token|secret|password|passwd|private[_-]?key)[A-Za-z0-9_-]{0,80})';
const SCALAR_VALUE = String.raw`(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|\$\{[^\r\n}]*\}|[^\s,}#]+)`;
const SECRET_ASSIGNMENT = new RegExp(String.raw`(["']?(${SECRET_KEY})["']?\s*[:=]\s*)(${SCALAR_VALUE})`, 'gi');
const TOKEN_PATTERNS = [
  /\b(?:sk|rk)-(?:proj-|svcacct-)?[A-Za-z0-9_-]{12,}\b/g,
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/g,
];

/** Applied to every evidence field, including metadata. Never include original input in reports. */
export function redact(value) {
  let text = String(value);
  text = text.replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)/g, '[已脱敏：私钥]');
  for (const pattern of TOKEN_PATTERNS) text = text.replace(pattern, '[已脱敏：令牌]');
  text = text.replace(/(\b(?:Bearer|Basic)\s+)[A-Za-z0-9+/_.=-]{8,}/gi, '$1[已脱敏]');
  text = text.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[已脱敏]@');
  text = text.replace(/([?&](?:key|token|api_key|apikey|secret|password|access_token)=)[^\s&#)"']+/gi, '$1[已脱敏]');
  text = text.replace(SECRET_ASSIGNMENT, (match, prefix, key, scalar) => {
    const raw = scalarValue(scalar);
    const quote = /^["']/.test(scalar) ? scalar[0] : '';
    if (isReference(raw) || isPlaceholder(raw)) return match;
    return `${prefix}${quote}[已脱敏]${quote}`;
  });
  return text;
}

function scalarValue(scalar) {
  if (scalar.startsWith('"') && scalar.endsWith('"')) {
    try { return JSON.parse(scalar); } catch { return scalar.slice(1, -1); }
  }
  return scalar.startsWith("'") && scalar.endsWith("'") ? scalar.slice(1, -1) : scalar;
}

function isReference(value) {
  return /^(?:\$\{[A-Za-z_][\w]*(?::[^}]*)?\}|\$[A-Za-z_][\w]*|process\.env(?:\.[\w]+|\[[^\]]+\])|os\.(?:getenv\([^)]*\)|environ(?:\[[^\]]+\]|\.get\([^)]*\))))$/.test(value);
}

function isPlaceholder(value) {
  return /^(?:|\[已脱敏(?::[^\]]+)?\]|<[^>]+>|YOUR[_ -][A-Z0-9_ -]+|REPLACE[_ -]?ME|CHANGEME|xxx+|example|dummy|test|null|undefined|true|false)$/i.test(value);
}

function excerpt(value, max = 260) {
  const safe = redact(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  return safe.length > max ? `${safe.slice(0, max)}…` : safe;
}

function linesOf(text) { return text.split(/\r?\n/); }
function lineAt(starts, offset) {
  let low = 0;
  let high = starts.length;
  while (low + 1 < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= offset) low = middle;
    else high = middle;
  }
  return low + 1;
}

function normalizeDomain(value) {
  if (typeof value !== 'string' || value.length > 253) throw new Error('允许域名必须是有效的域名字符串。');
  const normalized = value.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized || /[\s/:@?#*]/.test(normalized) || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(normalized) || normalized.includes('..')) {
    throw new Error(`允许域名格式无效：${excerpt(value, 80)}。请填写 example.com，不要填写 URL 或通配符。`);
  }
  return normalized;
}

function readFrontmatter(text) {
  const lines = linesOf(text.replace(/^\uFEFF/, ''));
  if (lines[0]?.trim() !== '---') return { fields: {}, present: false, closed: false };
  const end = lines.findIndex((line, i) => i > 0 && /^(?:---|\.\.\.)\s*$/.test(line));
  if (end < 0) return { fields: {}, present: true, closed: false };
  const fields = {};
  for (let i = 1; i < end; i++) {
    const match = /^(name|description)\s*:\s*(.*?)\s*$/.exec(lines[i]);
    if (!match) continue;
    let value = match[2];
    if (/^[|>][-+]?\s*(?:#.*)?$/.test(value)) {
      const block = [];
      while (i + 1 < end && (/^\s+/.test(lines[i + 1]) || !lines[i + 1].trim())) block.push(lines[++i].trim());
      value = block.join(' ').trim();
    } else {
      value = value.replace(/\s+#.*$/, '').replace(/^(['"])(.*)\1$/, '$2').trim();
    }
    if (value && !/^(?:null|~)$/i.test(value)) fields[match[1]] = value;
  }
  return { fields, present: true, closed: true };
}

const RULES = [
  {
    id: 'EXEC_REMOTE_PIPE', severity: 'high', category: '命令执行', title: '远程内容直接交给 Shell 执行',
    pattern: /\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|fish)\b/gi,
    why: '下载内容与执行连在一起，远端内容变化可能改变实际行为。规则不会下载或执行它；示例文本也可能命中。',
    recommendation: '先下载并人工审阅，固定版本与校验和；在隔离环境按最小权限运行。',
  },
  {
    id: 'EXEC_DESTRUCTIVE', severity: 'high', category: '命令执行', title: '发现可能删除或覆写数据的命令',
    pattern: /\brm\s+(?=[^\n;&|]*(?:-[a-zA-Z]*r|--recursive))(?=[^\n;&|]*(?:-[a-zA-Z]*f|--force))[^\n;&|]+|\b(?:mkfs(?:\.[a-z0-9]+)?|wipefs)\s+(?:-[^\s]+\s+)*\/dev\/[^\s]+|\bdd\s+[^\n]*\bof=\/dev\/[^\s]+|\b(?:Remove-Item|del)\s+[^\n]*(?:-Recurse|\/s)\b/gi,
    why: '文本含递归强制删除、格式化或设备写入等操作；影响范围取决于参数与运行目录。',
    recommendation: '确认目标路径并保留备份，替换为需明确确认的有限范围操作。不要直接复制执行。',
  },
  {
    id: 'EXEC_SUDO', severity: 'medium', category: '权限', title: '命令请求管理员权限',
    pattern: /(?:^|[\s`$;&|])sudo\s+(?:-[a-zA-Z]+\s+)*(?:rm|chmod|chown|bash|sh|zsh|curl|wget|apt(?:-get)?|yum|dnf|brew|pip3?|npm|node|python3?|install|tee|systemctl|docker|cp|mv|mkdir)\b/gim,
    why: '管理员权限会扩大命令影响范围；静态文本不能证明业务上确实需要提权。',
    recommendation: '用普通用户完成操作；需要提权时，逐项说明目的、路径与审批责任人。',
  },
  {
    id: 'PERMISSION_BYPASS', severity: 'high', category: '权限', title: '发现跳过权限检查或全量授权配置',
    pattern: /--(?:dangerously-skip-permissions|allow-all|yolo)\b|["'](?:dangerouslySkipPermissions|skipPermissions|bypassPermissions)["']\s*:\s*true|["']?(?:permissionMode|approval_policy)["']?\s*[:=]\s*["'](?:bypassPermissions|never)["']|["']?(?:allowedTools|allowed_tools|permissions)["']?\s*[:=]\s*(?:\[\s*)?["']\*["']/gi,
    why: '此类选项可能绕过执行前审批或授予全部工具权限，具体语义需按对应工具文档核实。',
    recommendation: '改成明确的工具、目录与操作允许清单，并保留敏感操作审批。',
  },
  {
    id: 'PROMPT_OVERRIDE', severity: 'high', category: '指令边界', title: '发现试图覆盖上层指令的措辞',
    pattern: /\bignore\s+(?:(?:all|any|the|your)\s+)*(?:(?:previous|prior|system|developer|safety|security)\s+)+(?:instructions?|prompts?|rules?|polic(?:y|ies))\b|\bbypass\s+(?:(?:all|the|your)\s+)*(?:safety|security)\s+(?:checks?|rules?|filters?|restrictions?|polic(?:y|ies))\b|忽略(?:此前|之前|先前|以上|所有|原有)?(?:的)?(?:系统|开发者|安全)(?:的)?(?:指令|提示|规则|限制)|无视(?:所有|之前|系统|安全)*(?:指令|规则|限制)/gi,
    why: '措辞可能诱导模型越过指令边界，也可能只是研究、测试或反面示例；需结合上下文审阅。',
    recommendation: '把外部文件与工具输出视为待处理数据，明确其不能修改上层指令或授权范围。',
  },
  {
    id: 'CONCEALMENT', severity: 'medium', category: '透明度', title: '发现隐瞒操作或静默传输的措辞',
    pattern: /\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify)\s+(?:the\s+)?user\b|\bhide\s+(?:this|these|the)\s+(?:action|operation|upload|request)s?\s+from\s+(?:the\s+)?user\b|(?:不要|不得|不必|无需)(?:向|让)?用户(?:透露|说明|报告|知晓)|(?:不要|不得|不必|无需)告诉用户|(?:静默|偷偷|暗中)(?:上传|发送|传输|外传)/gi,
    why: '指令可能降低用户对实际操作的可见性；上下文中的否定或教学示例可能导致误报。',
    recommendation: '明确说明收集的数据、目的地与触发条件，要求用户知情并按需确认。',
  },
  {
    id: 'CONFIG_PUBLIC_BIND', severity: 'medium', category: '网络配置', title: '服务可能监听所有网络接口',
    pattern: /["']?(?:host|bind|listen|address)["']?\s*[:=]\s*["']?(?:0\.0\.0\.0|::)["']?/gi,
    why: '全接口监听可能使本地服务被其他设备访问；是否暴露还取决于防火墙、容器和鉴权。',
    recommendation: '本机工具优先绑定 127.0.0.1；需远程访问时核实鉴权、传输加密与网络边界。',
  },
];

const NPX_RULE = { id: 'NPX_UNPINNED', severity: 'medium', category: '供应链', title: 'npx 包没有固定到精确版本', why: '未指定精确版本、使用 latest 或版本范围时，同一命令在不同时间可能运行不同代码。', recommendation: '固定到明确的 x.y.z 版本，审查包来源与发布者；固定版本仍不等于可信。' };
function isPinnedPackage(pkg) { return /@(?:v?\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?)$/.test(pkg); }
function npxPackages(args) {
  const explicit = [];
  let positional;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--package' || arg === '-p') { if (args[index + 1]) explicit.push(args[++index]); continue; }
    if (arg.startsWith('--package=')) { explicit.push(arg.slice(10)); continue; }
    if (['--cache', '--userconfig', '--registry', '--prefix', '-c', '--call'].includes(arg)) { index++; continue; }
    if (arg === '--') { if (!positional) positional = args[index + 1]; break; }
    if (!arg.startsWith('-') && !positional) positional = arg;
  }
  return explicit.length ? explicit : positional ? [positional] : [];
}
function jsonPropertyLine(text, key, lineStarts) {
  const escaped = JSON.stringify(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const matches = [...text.matchAll(new RegExp(`${escaped}\\s*:`, 'g'))];
  // A duplicate property name has no unambiguous source location without a source-map parser.
  return matches.length === 1 ? lineAt(lineStarts, matches[0].index) : 1;
}

/** @param {{name:string, content:string}[]} files */
export async function analyzeFiles(files, options = {}) {
  if (!Array.isArray(files) || !files.length) throw new Error('请至少提供一个可分析的文本文件。');
  if (files.length > LIMITS.maxFiles) throw new Error(`最多分析 ${LIMITS.maxFiles} 个文件。`);
  if (!options || typeof options !== 'object') throw new Error('分析选项必须是对象。');
  if (options.allowedDomains !== undefined && !Array.isArray(options.allowedDomains)) throw new Error('allowedDomains 必须是域名数组。');
  const allowedDomains = [...new Set((options.allowedDomains || []).map(normalizeDomain))];
  const prepared = [];
  let totalBytes = 0;
  const names = new Set();
  for (const file of files) {
    if (!file || typeof file.name !== 'string' || !file.name.trim() || typeof file.content !== 'string') throw new Error('每个文件都必须包含非空 name 和字符串 content。');
    if (file.name.length > 1024) throw new Error('文件名过长，最多支持 1024 个字符。');
    if (names.has(file.name)) throw new Error(`文件名重复：${excerpt(file.name, 120)}。`);
    names.add(file.name);
    const extension = /\.[^.\/\\]+$/.exec(file.name)?.[0]?.toLowerCase();
    if (!SUPPORTED_EXTENSIONS.includes(extension)) throw new Error(`不支持的文件格式：${excerpt(file.name, 120)}。`);
    if (file.content.includes('\0')) throw new Error(`文件似乎包含二进制内容：${excerpt(file.name, 120)}。`);
    const bytes = encoder.encode(file.content);
    if (bytes.length > LIMITS.maxFileBytes) throw new Error(`单个文件不能超过 1 MB：${excerpt(file.name, 120)}。`);
    totalBytes += bytes.length;
    if (totalBytes > LIMITS.maxTotalBytes) throw new Error('文件总大小不能超过 5 MB。');
    prepared.push({ ...file, encoded: bytes });
  }
  if (!globalThis.crypto?.subtle) throw new Error('当前环境不支持 SHA-256，请使用现代浏览器的 HTTPS / localhost 页面，或 Node.js 20 及以上。');

  const findings = [];
  const domains = new Set();
  const envVars = new Set();
  const commands = new Set();
  const metadata = [];
  const fileRecords = [];
  const seen = new Set();
  let capped = false;
  let skillCount = 0;
  const add = (file, rule, line, evidence, extra = {}) => {
    const key = `${file}\0${rule.id}\0${line}\0${extra.dedup || ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    if (findings.length >= 1000) { capped = true; return; }
    findings.push({ id: `F${String(findings.length + 1).padStart(4, '0')}`, ruleId: rule.id, severity: rule.severity, category: rule.category, title: rule.title, file: excerpt(file, 1024), line, evidence: excerpt(evidence), why: rule.why, recommendation: rule.recommendation });
  };

  for (const file of prepared) {
    const text = file.content;
    const lines = linesOf(text);
    const lineStarts = [0];
    for (let index = 0; index < text.length; index++) if (text[index] === '\n') lineStarts.push(index + 1);
    const hash = await globalThis.crypto.subtle.digest('SHA-256', file.encoded);
    fileRecords.push({ name: excerpt(file.name, 1024), bytes: file.encoded.length, sha256: [...new Uint8Array(hash)].map(byte => byte.toString(16).padStart(2, '0')).join('') });
    if (/(?:^|[\\/])SKILL\.md$/i.test(file.name)) {
      skillCount++;
      const frontmatter = readFrontmatter(text);
      metadata.push({ file: excerpt(file.name, 1024), name: excerpt(frontmatter.fields.name || '', 120), description: excerpt(frontmatter.fields.description || '', 300) });
      const missing = ['name', 'description'].filter(field => !frontmatter.fields[field]);
      if (missing.length) add(file.name, { id: 'SKILL_METADATA_MISSING', severity: 'medium', category: '接入格式', title: `SKILL.md 缺少必填元数据：${missing.join('、')}`, why: '技能入口通常通过开头的 YAML frontmatter 提供 name 和 description；缺失或未闭合时可能无法被正确发现。此处只解析常见字段写法。', recommendation: '在文件开头添加 --- 包围的 YAML 区块，填写非空 name 和 description，再用目标客户端验证加载。' }, 1, frontmatter.present && !frontmatter.closed ? '检测到未闭合的 frontmatter。' : `缺少字段：${missing.join(', ')}`);
    }

    if (/\.json$/i.test(file.name)) {
      let config;
      try { config = JSON.parse(text.replace(/^\uFEFF/, '')); }
      catch {
        add(file.name, { id: 'JSON_PARSE_ERROR', severity: 'medium', category: '接入格式', title: 'JSON 文件无法按标准 JSON 解析', why: '结构检查无法完成；后续仍执行文本规则。注释、尾逗号或语法错误都可能造成此提示。', recommendation: '修复 JSON 格式并用目标客户端重新验证配置；本工具不把 JSONC 当作标准 JSON。' }, 1, 'JSON 结构解析失败，未读取服务配置结构。');
      }
      if (config && typeof config === 'object' && !Array.isArray(config)) {
        for (const rootKey of ['mcpServers', 'servers']) {
          const servers = config[rootKey];
          if (!servers || typeof servers !== 'object' || Array.isArray(servers)) continue;
          for (const [serverName, server] of Object.entries(servers)) {
            if (!server || typeof server !== 'object' || Array.isArray(server)) continue;
            if (server.env && typeof server.env === 'object' && !Array.isArray(server.env)) {
              for (const name of Object.keys(server.env)) if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) envVars.add(name);
            }
            if (typeof server.command !== 'string') continue;
            const command = server.command.split(/[\\/]/).pop().replace(/\.(?:cmd|exe)$/i, '').trim();
            if (command) commands.add(excerpt(command, 80));
            if (command.toLowerCase() !== 'npx' || !Array.isArray(server.args) || !server.args.every(arg => typeof arg === 'string')) continue;
            const serverLine = jsonPropertyLine(text, serverName, lineStarts);
            for (const pkg of npxPackages(server.args)) {
              if (isPinnedPackage(pkg)) continue;
              add(file.name, NPX_RULE, serverLine, `MCP 服务 ${serverName}: command=npx；包=${pkg}（位置为服务定义；重名时定位文件开头）`, { dedup: `${rootKey}.${serverName}.${pkg}` });
            }
          }
        }
      }
    }

    // Preserve offsets while allowing shell continuation between pipe and interpreter.
    const searchable = text.replace(/\\\r?\n/g, match => ' '.repeat(match.length));
    for (const rule of RULES) {
      for (const match of searchable.matchAll(rule.pattern)) {
        const line = lineAt(lineStarts, match.index);
        add(file.name, rule, line, lines[line - 1] || match[0]);
      }
    }

    for (const match of text.matchAll(/\b(?:https?|wss?):\/\/[^\s<>"'`\]\[(){}]+/gi)) {
      let url;
      try { url = new URL(match[0].replace(/[.,;!]+$/, '')); } catch { continue; }
      const domain = url.hostname.toLowerCase().replace(/\.$/, '');
      if (!domain) continue;
      domains.add(domain);
      const allowed = allowedDomains.some(item => domain === item || domain.endsWith(`.${item}`));
      const unlisted = allowedDomains.length > 0 && !allowed;
      add(file.name, { id: unlisted ? 'DOMAIN_NOT_ALLOWED' : 'EXTERNAL_DOMAIN', severity: unlisted ? 'medium' : 'info', category: '外部地址', title: `${unlisted ? '域名不在允许清单内' : '发现外部地址域名'}：${domain}`, why: unlisted ? '该域名不在本次显式允许清单中；URL 也可能只是引用或文档链接，不能据此断言发生了联网。' : '这是文本中出现的 URL 域名清单，可能是文档、示例或实际访问目标；本工具不会访问该地址。', recommendation: '确认域名用途、所有者和可能传输的数据。允许清单只影响此项提示，不会关闭命令或密钥检查。' }, lineAt(lineStarts, match.index), `${url.protocol}//${domain}${url.port ? `:${url.port}` : ''}（路径、凭据与查询参数不收录）`, { dedup: domain });
    }

    const envPatterns = [ /\$\{([A-Z_][A-Z0-9_]*)(?::[^}]*)?\}|\$([A-Z_][A-Z0-9_]*)\b/g, /process\.env\.([A-Z_][A-Z0-9_]*)\b/g, /(?:process\.env|os\.environ)\[['"]([A-Z_][A-Z0-9_]*)['"]\]/g, /(?:os\.getenv|os\.environ\.get)\(['"]([A-Z_][A-Z0-9_]*)['"]/g ];
    for (const pattern of envPatterns) for (const match of text.matchAll(pattern)) envVars.add(match[1] || match[2]);
    for (const match of text.matchAll(/(?:^|[\s`$;&|])(?:sudo\s+)?(curl|wget|bash|sh|zsh|fish|npx|npm|pnpm|yarn|pip3?|python3?|node|rm|chmod|chown|docker|git|mkfs|dd)\s+(?=[^\s])/gim)) commands.add(match[1].toLowerCase());

    for (let index = 0; index < lines.length; index++) {
      const line = lines[index];
      for (const match of line.matchAll(SECRET_ASSIGNMENT)) {
        const value = scalarValue(match[3]);
        const key = match[2];
        if (/^[A-Z_][A-Z0-9_]*$/.test(key)) envVars.add(key);
        if (value.length < 8 || isReference(value) || isPlaceholder(value) || /^(?:os\.|process\.|getenv\(|environ\[)/.test(value)) continue;
        add(file.name, { id: 'SECRET_LITERAL', severity: 'high', category: '凭据', title: `疑似明文凭据：${excerpt(key, 80)}`, why: '具有凭据含义的字段被赋予文字值，可能把真实凭据带入仓库或配置；也可能是示例值。报告仅保留脱敏证据。', recommendation: '改用环境变量或凭据存储。如果是真实有效的凭据，先撤销或轮换，再清理工作区与提交历史。' }, index + 1, line);
      }
      const hasToken = TOKEN_PATTERNS.some(pattern => { pattern.lastIndex = 0; return pattern.test(line); });
      if (hasToken || /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(line)) add(file.name, { id: 'SECRET_TOKEN_PATTERN', severity: 'high', category: '凭据', title: '发现疑似令牌或私钥格式', why: '文本匹配常见令牌或私钥特征；不验证其有效性，也不发送到网络。', recommendation: '核实是否为真实凭据。真实凭据应撤销或轮换，迁移至安全的凭据存储。' }, index + 1, line);
      for (const match of line.matchAll(/\bnpx\s+(?:(?:-y|--yes|--no-install)\s+)*(?:(?:--package(?:=|\s+)|-p\s+))?((?:@[\w.-]+\/)?[\w.-]+(?:@[^\s`"';&|]+)?)/g)) {
        const pkg = match[1];
        if (isPinnedPackage(pkg)) continue;
        add(file.name, NPX_RULE, index + 1, line);
      }
    }
  }
  const summary = { high: 0, medium: 0, info: 0, total: findings.length, skillCount };
  for (const finding of findings) summary[finding.severity]++;
  const limitations = [
    '仅做本地静态文本匹配；未执行命令、未安装依赖、未访问域名，也未验证凭据是否有效。',
    '可能存在误报和漏报；注释、引用、反面示例也可能命中，混淆、动态拼接及运行时行为可能漏检。',
    '未命中规则不代表安全认证。请结合来源、版本、实际权限、数据范围与隔离环境测试做接入决定。',
    '报告不含全量原文，证据会截断并按已知模式脱敏；未知格式的敏感信息仍需导出前人工检查。',
    'SKILL frontmatter 只识别常见 name / description 字段与简单块标量，不替代完整 YAML 或客户端验证。',
  ];
  if (allowedDomains.length) limitations.push(`域名允许清单：${allowedDomains.join('、')}；包含其子域，仅改变域名提示级别，不改变其他规则。`);
  if (capped) limitations.push('命中结果超过 1000 条，报告只保留前 1000 条；统计并非全部命中，请拆分文件重新分析。');
  return { schemaVersion: '1.0.0', generatedAt: new Date().toISOString(), files: fileRecords, summary, findings, inventory: { domains: [...domains].sort(), envVars: [...envVars].sort(), commands: [...commands].sort(), metadata }, coverage: { scannedFiles: files.length, totalBytes, limitations } };
}
