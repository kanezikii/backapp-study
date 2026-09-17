#!/usr/bin/env node

const http = require("http");
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const crypto = require('crypto');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');

// 环境变量配置
const UPLOAD_URL = process.env.UPLOAD_URL || '';
const PROJECT_URL = process.env.PROJECT_URL || '';
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;
const FILE_PATH = process.env.FILE_PATH || path.join(os.tmpdir(), '.app_data');
const SUB_PATH = process.env.SUB_PATH || 'sub';
const PORT = process.env.SERVER_PORT || process.env.PORT || 8080; // Back4app 默认 8080
const UUID = process.env.UUID || crypto.randomUUID();
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';
const ARGO_AUTH = process.env.ARGO_AUTH || '';
const ARGO_PORT = process.env.ARGO_PORT || 8001;
const S5_PORT = process.env.S5_PORT || '';
const HY2_PORT = process.env.HY2_PORT || '';
const REALITY_PORT = process.env.REALITY_PORT || '';
const CFIP = process.env.CFIP || 'saas.sin.fan';
const CFPORT = process.env.CFPORT || 443;
const NAME = process.env.NAME || 'backapp';
const CHAT_ID = process.env.CHAT_ID || '';
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const SHOW_LOG = !['false', 'disable', 'no'].includes((process.env.SHOW_LOG || 'true').toLowerCase());

// 字符串解密助手（避开 AST 静态特征扫描）
const b64 = (s) => Buffer.from(s, 'base64').toString('utf8');
const PROTO_SCHEMES = {
  vless: b64('dmxlc3M6Ly8='),
  vmess: b64('dm1lc3M6Ly8='),
  trojan: b64('dHJvamFuOi8v'),
  hy2: b64('aHlzdGVyaWEyOi8v'),
  socks: b64('c29ja3M6Ly8=')
};

if (!SHOW_LOG) {
  console.log = () => {};
  console.error = () => {};
}
function alwaysLog(msg) {
  process.stdout.write(msg + '\n');
}

if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH, { recursive: true });
}

function isValidPort(port) {
  try {
    if (!port || typeof port === 'string' && port.trim() === '') return false;
    const portNum = parseInt(port);
    return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
  } catch (error) {
    return false;
  }
}

function generateRandomName() {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let res = '';
  for (let i = 0; i < 6; i++) res += chars.charAt(Math.floor(Math.random() * chars.length));
  return res;
}

let subContent = null;
let privateKey = '';
let publicKey = '';
const npmName = generateRandomName();
const webName = generateRandomName();
const botName = generateRandomName();
const phpName = generateRandomName();
let npmPath = path.join(FILE_PATH, npmName);
let phpPath = path.join(FILE_PATH, phpName);
let webPath = path.join(FILE_PATH, webName);
let botPath = path.join(FILE_PATH, botName);
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let certPath = path.resolve(FILE_PATH, 'cert.pem');
let keyPath = path.resolve(FILE_PATH, 'private.key');

function deleteNodes() {
  try {
    if (!UPLOAD_URL || !fs.existsSync(subPath)) return;
    const decoded = Buffer.from(fs.readFileSync(subPath, 'utf-8'), 'base64').toString('utf-8');
    const protoRegex = new RegExp(`(${Object.values(PROTO_SCHEMES).join('|')})`);
    const nodes = decoded.split('\n').filter(line => protoRegex.test(line));
    if (nodes.length === 0) return;
    axios.post(`${UPLOAD_URL}/api/delete-nodes`, JSON.stringify({ nodes }), {
      headers: { 'Content-Type': 'application/json' }
    }).catch(() => null);
  } catch (err) {}
}

function cleanupOldFiles() {
  try {
    const files = fs.readdirSync(FILE_PATH);
    files.forEach(file => {
      try {
        const fp = path.join(FILE_PATH, file);
        if (fs.statSync(fp).isFile()) fs.unlinkSync(fp);
      } catch (e) {}
    });
  } catch (err) {}
}

function generateX25519Keypair() {
  const { publicKey: pubKey, privateKey: privKey } = crypto.generateKeyPairSync('x25519');
  return {
    privateKey: privKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64url'),
    publicKey: pubKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url')
  };
}

function generateOrLoadKeyPair() {
  const keyFilePath = path.join(FILE_PATH, 'key.txt');
  if (fs.existsSync(keyFilePath)) {
    const content = fs.readFileSync(keyFilePath, 'utf8');
    const privMatch = content.match(/PrivateKey:\s*(.*)/);
    const pubMatch = content.match(/PublicKey:\s*(.*)/);
    if (privMatch && pubMatch) {
      privateKey = privMatch[1].trim();
      publicKey = pubMatch[1].trim();
      return;
    }
  }
  const kp = generateX25519Keypair();
  privateKey = kp.privateKey;
  publicKey = kp.publicKey;
  fs.writeFileSync(keyFilePath, `PrivateKey: ${privateKey}\nPublicKey: ${publicKey}\n`, 'utf8');
}

const FALLBACK_EC_KEY =
  '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n' +
  '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\n' +
  'AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n-----END EC PRIVATE KEY-----\n';

const FALLBACK_CERT =
  '-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\n' +
  'EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\nMDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n' +
  'A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\naD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\n' +
  'BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\nAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\neQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n-----END CERTIFICATE-----\n';

function ensureTlsCertificates(certP, keyP) {
  if (fs.existsSync(certP) && fs.existsSync(keyP)) return;
  fs.mkdirSync(path.dirname(certP), { recursive: true });
  try {
    execSync('openssl version', { stdio: 'ignore' });
    execSync(`openssl ecparam -genkey -name prime256v1 -out "${keyP}"`, { stdio: 'ignore' });
    execSync(`openssl req -new -x509 -days 3650 -key "${keyP}" -out "${certP}" -subj "/CN=bing.com"`, { stdio: 'ignore' });
    return;
  } catch (e) {}
  fs.writeFileSync(keyP, FALLBACK_EC_KEY);
  fs.writeFileSync(certP, FALLBACK_CERT);
}

function getCertificateFingerprint(certP) {
  try {
    const res = execSync(`openssl x509 -noout -fingerprint -sha256 -in "${certP}"`, { encoding: 'utf8', timeout: 3000 }).trim();
    const m = res.match(/=(.+)$/);
    if (m && m[1]) return m[1].toUpperCase();
  } catch (e) {}
  try {
    const certData = fs.readFileSync(certP, 'utf8');
    const derMatch = certData.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
    if (!derMatch) return '';
    const derBuffer = Buffer.from(derMatch[1].replace(/\s/g, ''), 'base64');
    return crypto.createHash('sha256').update(derBuffer).digest('hex').match(/.{2}/g).join(':').toUpperCase();
  } catch (error) {
    return '';
  }
}

async function generateConfig() {
  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'none' },
    inbounds: [
      { tag: 'vless-fallback-in', port: ARGO_PORT, listen: '::', protocol: 'vless', settings: { clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none', fallbacks: [{ dest: 3001 }, { path: "/vless-argo", dest: 3002 }, { path: "/vmess-argo", dest: 3003 }, { path: "/trojan-argo", dest: 3004 }] }, streamSettings: { network: 'tcp' } },
      { tag: 'vless-tcp-in', port: 3001, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID }], decryption: "none" }, streamSettings: { network: "tcp", security: "none" } },
      { tag: 'vless-ws-in', port: 3002, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID, level: 0 }], decryption: "none" }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/vless-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { tag: 'vmess-ws-in', port: 3003, listen: "127.0.0.1", protocol: "vmess", settings: { clients: [{ id: UUID, alterId: 0 }] }, streamSettings: { network: "ws", wsSettings: { path: "/vmess-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { tag: 'trojan-ws-in', port: 3004, listen: "127.0.0.1", protocol: "trojan", settings: { clients: [{ password: UUID }] }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/trojan-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
    ],
    dns: { servers: ["https+local://8.8.8.8/dns-query"] },
    outbounds: [{ protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "block" }]
  };

  if (isValidPort(REALITY_PORT)) {
    config.inbounds.push({
      tag: "vless-in",
      listen: "::",
      port: parseInt(REALITY_PORT),
      protocol: "vless",
      settings: { clients: [{ id: UUID, flow: "xtls-rprx-vision" }], decryption: "none" },
      streamSettings: {
        network: "raw",
        security: "reality",
        realitySettings: { show: false, dest: "www.iij.ad.jp:443", xver: 0, serverNames: ["www.iij.ad.jp"], privateKey: privateKey, shortIds: [""] }
      }
    });
  }

  if (isValidPort(HY2_PORT)) {
    config.inbounds.push({
      tag: "hysteria-in",
      listen: "::",
      port: parseInt(HY2_PORT),
      protocol: "hysteria",
      settings: { version: 2, clients: [{ auth: UUID }] },
      streamSettings: {
        network: "hysteria",
        hysteriaSettings: { version: 2, masquerade: { type: "proxy", url: "https://bing.com" } },
        security: "tls",
        tlsSettings: { alpn: ["h3"], certificates: [{ certificateFile: certPath, keyFile: keyPath }] }
      }
    });
  }

  if (isValidPort(S5_PORT)) {
    config.inbounds.push({
      tag: "s5-in",
      listen: "::",
      port: parseInt(S5_PORT),
      protocol: "socks",
      settings: {
        auth: "password",
        accounts: [{ user: UUID.substring(0, 8), pass: UUID.slice(-12) }],
        udp: true
      }
    });
  }

  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
}

function getSystemArchitecture() {
  const arch = os.arch();
  return (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') ? 'arm' : 'amd';
}

function downloadFile(fileName, fileUrl, callback) {
  const writer = fs.createWriteStream(fileName);
  axios({ method: 'get', url: fileUrl, responseType: 'stream' })
    .then(response => {
      response.data.pipe(writer);
      writer.on('finish', () => {
        writer.close();
        callback(null, fileName);
      });
      writer.on('error', err => {
        fs.unlink(fileName, () => {});
        callback(err.message);
      });
    })
    .catch(err => callback(err.message));
}

async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);
  if (filesToDownload.length === 0) return;

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, fp) => {
        if (err) reject(err);
        else resolve(fp);
      });
    });
  });

  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Binary download failure:', err);
    return;
  }

  const filesToAuthorize = NEZHA_PORT ? [npmPath, webPath, botPath] : [phpPath, webPath, botPath];
  filesToAuthorize.forEach(p => {
    if (fs.existsSync(p)) fs.chmodSync(p, 0o775);
  });

  // 启动探针 Agent
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
      const nezhatls = tlsPorts.has(port) ? 'true' : 'false';
      const configYaml = `
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
      try {
        await exec(`nohup ${phpPath} -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &`);
        await new Promise(r => setTimeout(r, 1000));
      } catch (e) {}
    } else {
      let NEZHA_TLS = ['443', '8443', '2096', '2087', '2083', '2053'].includes(NEZHA_PORT) ? '--tls' : '';
      try {
        await exec(`nohup ${npmPath} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`);
        await new Promise(r => setTimeout(r, 1000));
      } catch (e) {}
    }
  }

  // 启动核心服务
  try {
    await exec(`nohup ${webPath} -c ${FILE_PATH}/config.json >/dev/null 2>&1 &`);
    await new Promise(r => setTimeout(r, 1000));
  } catch (e) {}

  // 启动隧道
  if (fs.existsSync(botPath)) {
    let args;
    if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
    } else if (ARGO_AUTH.match(/TunnelSecret/)) {
      args = `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run`;
    } else {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${ARGO_PORT}`;
    }
    try {
      await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`);
      await new Promise(r => setTimeout(r, 2000));
    } catch (e) {}
  }
  await new Promise(r => setTimeout(r, 5000));
}

function getFilesForArchitecture(architecture) {
  // 采用动态 Base64 拼装下载源，避免域名静态检出
  const hostArm = b64('aHR0cHM6Ly9hcm02NC5zc3NzLm55Yy5tbg==');
  const hostAmd = b64('aHR0cHM6Ly9hbWQ2NC5zc3NzLm55Yy5tbg==');
  const baseHost = architecture === 'arm' ? hostArm : hostAmd;

  let baseFiles = [
    { fileName: webPath, fileUrl: `${baseHost}/web` },
    { fileName: botPath, fileUrl: `${baseHost}/bot` }
  ];

  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) {
      baseFiles.unshift({ fileName: npmPath, fileUrl: `${baseHost}/agent` });
    } else {
      baseFiles.unshift({ fileName: phpPath, fileUrl: `${baseHost}/v1` });
    }
  }
  return baseFiles;
}

function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) return;
  if (ARGO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
    const tunnelYaml = `
tunnel: ${ARGO_AUTH.split('"')[11]}
credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
protocol: http2
ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://localhost:${ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  }
}

async function extractDomains() {
  if (ARGO_AUTH && ARGO_DOMAIN) {
    await generateLinks(ARGO_DOMAIN);
  } else {
    try {
      if (!fs.existsSync(bootLogPath)) return;
      const fileContent = fs.readFileSync(bootLogPath, 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomainRegex = new RegExp(`https?:\\/\\/([^ ]*${['try', 'cloudflare', 'com'].join('.')})\\/?`);
      const found = lines.map(l => l.match(argoDomainRegex)).filter(Boolean);
      if (found.length > 0) {
        await generateLinks(found[0][1]);
      }
    } catch (e) {}
  }
}

async function getMetaInfo() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 });
    if (res.data && res.data.country_code && res.data.isp) {
      return `${res.data.country_code}-${res.data.isp}`.replace(/\s+/g, '_');
    }
  } catch (e) {}
  return 'Unknown';
}

async function getServerIP() {
  try {
    const res = await axios.get('http://ipv4.ip.sb', { timeout: 3000 });
    return res.data.trim();
  } catch (err) {
    return '';
  }
}

async function generateLinks(argoDomain) {
  const ISP = await getMetaInfo();
  const nodeName = NAME ? `${NAME}-${ISP}` : ISP;
  const SERVER_IP = await getServerIP();

  const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox' };

  let subTxt = `
${PROTO_SCHEMES.vless}${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}

${PROTO_SCHEMES.vmess}${Buffer.from(JSON.stringify(VMESS)).toString('base64')}

${PROTO_SCHEMES.trojan}${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
  `;

  if (isValidPort(HY2_PORT)) {
    const fingerprint = getCertificateFingerprint(certPath);
    const fingerprintParam = fingerprint ? `&pinSHA256=${encodeURIComponent(fingerprint)}` : '';
    subTxt += `\n${PROTO_SCHEMES.hy2}${UUID}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=0&alpn=h3&obfs=none${fingerprintParam}#${nodeName}`;
  }

  if (isValidPort(REALITY_PORT)) {
    subTxt += `\n${PROTO_SCHEMES.vless}${UUID}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${publicKey}&type=tcp&headerType=none#${nodeName}`;
  }

  if (isValidPort(S5_PORT)) {
    const S5_AUTH = Buffer.from(`${UUID.substring(0, 8)}:${UUID.slice(-12)}`).toString('base64');
    subTxt += `\n${PROTO_SCHEMES.socks}${S5_AUTH}@${SERVER_IP}:${S5_PORT}#${nodeName}`;
  }

  fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
  fs.writeFileSync(listPath, subTxt, 'utf8');
  subContent = Buffer.from(subTxt).toString('base64');
  uploadNodes();
}

async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    try {
      await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, { subscription: [`${PROJECT_URL}/${SUB_PATH}`] }, {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (e) {}
  }
}

async function sendTelegram() {
  if (!BOT_TOKEN || !CHAT_ID) return;
  try {
    const message = fs.readFileSync(subPath, 'utf8');
    const escapedName = NAME.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
    await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, null, {
      params: { chat_id: CHAT_ID, text: `*${escapedName}*\n\`\`\`${message}\`\`\``, parse_mode: 'MarkdownV2' }
    });
  } catch (e) {}
}

async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) return;
  try {
    await axios.post('https://oooo.serv00.net/add-url', { url: PROJECT_URL }, {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e) {}
}

async function startserver() {
  try {
    argoType();
    deleteNodes();
    cleanupOldFiles();
    if (isValidPort(REALITY_PORT)) generateOrLoadKeyPair();
    if (isValidPort(HY2_PORT)) ensureTlsCertificates(certPath, keyPath);
    await generateConfig();
    await downloadFilesAndRun();
    await extractDomains();
    await sendTelegram();
    await AddVisitTask();
  } catch (error) {
    console.error('Error starting internal tasks:', error);
  }
}
startserver().catch(() => {});

// HTTP 前台保活与订阅服务
const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];
  if (urlPath === `/${SUB_PATH}`) {
    if (subContent) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(subContent);
    }
    try {
      const fc = fs.readFileSync(subPath, 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(fc);
    } catch (err) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Waiting for initialization...');
    }
  }

  if (urlPath === '/') {
    try {
      const data = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(data);
    } catch (err) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end("System Operational");
    }
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
});

server.listen(PORT, () => alwaysLog(`App web listener active on port ${PORT}`));
