/**
 * CF-VLESS-SUB
 * Cloudflare Worker VLESS 代理 + 订阅管理 + 优选IP自动更新
 */

// ==================== 配置区域 ====================
const DEFAULT_CONFIG = {
  // 优选IP数据源（公开API）
  IP_SOURCES: [
    'https://ipdb.api.030101.xyz/?type=bestcf',
    'https://addressesapi.090227.xyz/CloudFlare',
    'https://cf.090227.xyz/CF_ipv4.txt',
  ],
  // 默认优选IP（备用）
  DEFAULT_IPS: [
    'icook.hk',
    'www.visa.com.hk',
    'www.csgo.com',
    'icook.tw',
    'cdn.anycast.eu.org',
    'time.cloudflare.com',
  ],
  // 默认端口列表
  PORTS: {
    https: [443, 8443, 2053, 2096, 2087, 2083],
    http: [80, 8080, 8880, 2052, 2082, 2086, 2095],
  },
};

// ==================== 主入口 ====================
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // 路由处理
      if (path === '/') {
        return handleHomePage(env);
      }
      
      // 管理面板
      if (path.startsWith('/admin')) {
        return handleAdmin(request, env, url);
      }
      
      // 订阅链接
      if (path.startsWith('/sub')) {
        return handleSubscribe(request, env, url);
      }
      
      // API接口
      if (path.startsWith('/api')) {
        return handleAPI(request, env, url);
      }
      
      // WebSocket VLESS 代理
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader === 'websocket') {
        return handleVLESSWebSocket(request, env);
      }
      
      // 默认返回伪装页面
      return handleHomePage(env);
      
    } catch (err) {
      return new Response(`Error: ${err.message}`, { status: 500 });
    }
  },

  // 定时任务 - 自动更新优选IP
  async scheduled(event, env, ctx) {
    ctx.waitUntil(updateBestIPs(env));
  },
};

// ==================== 管理面板 ====================
async function handleAdmin(request, env, url) {
  const password = env.ADMIN_PASS || 'admin123';
  const path = url.pathname;
  
  // 验证密码
  const authPass = url.searchParams.get('pass');
  if (authPass !== password) {
    return new Response(generateLoginPage(), {
      headers: { 'Content-Type': 'text/html;charset=utf-8' },
    });
  }

  // 保存配置
  if (request.method === 'POST' && path === '/admin/save') {
    const formData = await request.formData();
    const config = {
      uuid: formData.get('uuid') || env.UUID,
      proxyIP: formData.get('proxyIP') || '',
      customIPs: formData.get('customIPs') || '',
      nodeName: formData.get('nodeName') || 'CF-VLESS',
      autoUpdate: formData.get('autoUpdate') === 'on',
    };
    
    if (env.CFKV) {
      await env.CFKV.put('config', JSON.stringify(config));
    }
    
    return Response.redirect(`${url.origin}/admin?pass=${password}&saved=1`, 302);
  }

  // 手动更新优选IP
  if (path === '/admin/update-ip') {
    const result = await updateBestIPs(env);
    return Response.redirect(`${url.origin}/admin?pass=${password}&updated=1&count=${result.count}`, 302);
  }

  // 显示管理页面
  const config = await getConfig(env);
  const bestIPs = await getBestIPs(env);
  
  return new Response(generateAdminPage(config, bestIPs, url, password), {
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}

// ==================== 订阅处理 ====================
async function handleSubscribe(request, env, url) {
  const config = await getConfig(env);
  const uuid = config.uuid || env.UUID;
  
  if (!uuid) {
    return new Response('UUID not configured', { status: 500 });
  }

  const path = url.pathname;
  const host = request.headers.get('Host');
  const bestIPs = await getBestIPs(env);
  const nodeName = config.nodeName || 'CF-VLESS';
  
  // 不同格式的订阅
  if (path === '/sub/base64' || path === '/sub') {
    const nodes = generateNodes(uuid, host, bestIPs, nodeName);
    const base64 = btoa(nodes.join('\n'));
    return new Response(base64, {
      headers: {
        'Content-Type': 'text/plain;charset=utf-8',
        'Profile-Update-Interval': '6',
        'Subscription-Userinfo': 'upload=0; download=0; total=10737418240; expire=2099999999',
      },
    });
  }
  
  if (path === '/sub/clash') {
    const clashConfig = generateClashConfig(uuid, host, bestIPs, nodeName);
    return new Response(clashConfig, {
      headers: { 'Content-Type': 'text/yaml;charset=utf-8' },
    });
  }
  
  if (path === '/sub/singbox') {
    const singboxConfig = generateSingboxConfig(uuid, host, bestIPs, nodeName);
    return new Response(JSON.stringify(singboxConfig, null, 2), {
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  // 订阅中心页面
  return new Response(generateSubPage(host), {
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}

// ==================== API 接口 ====================
async function handleAPI(request, env, url) {
  const path = url.pathname;
  
  // 获取当前优选IP列表
  if (path === '/api/best-ips') {
    const bestIPs = await getBestIPs(env);
    return new Response(JSON.stringify(bestIPs), {
      headers: { 'Content-Type': 'application/json' },
    });
  }
  
  // 手动触发更新优选IP
  if (path === '/api/update-ips') {
    const result = await updateBestIPs(env);
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  }
  
  // 获取配置信息
  if (path === '/api/config') {
    const config = await getConfig(env);
    // 不返回敏感信息
    return new Response(JSON.stringify({
      nodeName: config.nodeName,
      autoUpdate: config.autoUpdate,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response('Not Found', { status: 404 });
}

// ==================== 优选IP更新 ====================
async function updateBestIPs(env) {
  let allIPs = new Set();
  
  // 从多个源获取IP
  for (const source of DEFAULT_CONFIG.IP_SOURCES) {
    try {
      const response = await fetch(source, {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        cf: { cacheTtl: 300 },
      });
      
      if (response.ok) {
        const text = await response.text();
        const ips = text.split(/[\n,\s]+/).filter(ip => ip.trim() && isValidIP(ip.trim()));
        ips.forEach(ip => allIPs.add(ip.trim()));
      }
    } catch (e) {
      console.log(`Failed to fetch from ${source}: ${e.message}`);
    }
  }
  
  // 如果没有获取到，使用默认IP
  if (allIPs.size === 0) {
    DEFAULT_CONFIG.DEFAULT_IPS.forEach(ip => allIPs.add(ip));
  }
  
  // 限制数量并保存
  const ipList = Array.from(allIPs).slice(0, 20);
  
  if (env.CFKV) {
    await env.CFKV.put('bestIPs', JSON.stringify({
      ips: ipList,
      updatedAt: new Date().toISOString(),
    }));
  }
  
  return { success: true, count: ipList.length, ips: ipList };
}

async function getBestIPs(env) {
  try {
    if (env.CFKV) {
      const data = await env.CFKV.get('bestIPs', 'json');
      if (data && data.ips && data.ips.length > 0) {
        return data;
      }
    }
  } catch (e) {
    console.log('Failed to get bestIPs from KV:', e.message);
  }
  
  // 获取自定义配置的IP
  const config = await getConfig(env);
  if (config.customIPs) {
    const customList = config.customIPs.split(/[\n,]+/).filter(ip => ip.trim());
    if (customList.length > 0) {
      return { ips: customList, updatedAt: 'custom' };
    }
  }
  
  return { ips: DEFAULT_CONFIG.DEFAULT_IPS, updatedAt: 'default' };
}

async function getConfig(env) {
  try {
    if (env.CFKV) {
      const config = await env.CFKV.get('config', 'json');
      if (config) return config;
    }
  } catch (e) {}
  
  return {
    uuid: env.UUID || '',
    proxyIP: env.PROXY_IP || '',
    customIPs: '',
    nodeName: 'CF-VLESS',
    autoUpdate: true,
  };
}

function isValidIP(str) {
  // 简单验证IP或域名格式
  if (!str || str.length < 4) return false;
  // IPv4
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(str)) return true;
  // 域名
  if (/^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$/.test(str)) return true;
  // IPv6
  if (str.includes(':') && /^[0-9a-fA-F:]+$/.test(str)) return true;
  return false;
}

// ==================== 节点生成 ====================
function generateNodes(uuid, host, bestIPData, nodeName) {
  const nodes = [];
  const ips = bestIPData.ips || DEFAULT_CONFIG.DEFAULT_IPS;
  
  // HTTPS 端口节点
  ips.forEach((ip, index) => {
    DEFAULT_CONFIG.PORTS.https.forEach(port => {
      const name = `${nodeName}-${index + 1}-${port}`;
      const node = `vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F#${encodeURIComponent(name)}`;
      nodes.push(node);
    });
  });
  
  return nodes;
}

function generateClashConfig(uuid, host, bestIPData, nodeName) {
  const ips = bestIPData.ips || DEFAULT_CONFIG.DEFAULT_IPS;
  const proxies = [];
  const proxyNames = [];
  
  ips.forEach((ip, index) => {
    DEFAULT_CONFIG.PORTS.https.forEach(port => {
      const name = `${nodeName}-${index + 1}-${port}`;
      proxyNames.push(name);
      proxies.push({
        name: name,
        type: 'vless',
        server: ip,
        port: port,
        uuid: uuid,
        network: 'ws',
        tls: true,
        udp: false,
        sni: host,
        'client-fingerprint': 'chrome',
        'ws-opts': {
          path: '/',
          headers: { Host: host },
        },
      });
    });
  });

  const config = {
    'mixed-port': 7890,
    'allow-lan': true,
    mode: 'rule',
    'log-level': 'info',
    dns: {
      enable: true,
      'enhanced-mode': 'fake-ip',
      nameserver: ['8.8.8.8', '1.1.1.1'],
    },
    proxies: proxies,
    'proxy-groups': [
      {
        name: 'Proxy',
        type: 'select',
        proxies: ['Auto', ...proxyNames],
      },
      {
        name: 'Auto',
        type: 'url-test',
        proxies: proxyNames,
        url: 'http://www.gstatic.com/generate_204',
        interval: 300,
      },
    ],
    rules: [
      'GEOIP,LAN,DIRECT',
      'GEOIP,CN,DIRECT',
      'MATCH,Proxy',
    ],
  };

  return generateYAML(config);
}

function generateSingboxConfig(uuid, host, bestIPData, nodeName) {
  const ips = bestIPData.ips || DEFAULT_CONFIG.DEFAULT_IPS;
  const outbounds = [];
  const tags = [];

  ips.slice(0, 5).forEach((ip, index) => {
    const tag = `${nodeName}-${index + 1}`;
    tags.push(tag);
    outbounds.push({
      type: 'vless',
      tag: tag,
      server: ip,
      server_port: 443,
      uuid: uuid,
      tls: {
        enabled: true,
        server_name: host,
        utls: { enabled: true, fingerprint: 'chrome' },
      },
      transport: {
        type: 'ws',
        path: '/',
        headers: { Host: host },
      },
    });
  });

  return {
    log: { level: 'info' },
    dns: {
      servers: [
        { tag: 'google', address: 'tls://8.8.8.8' },
        { tag: 'local', address: '223.5.5.5', detour: 'direct' },
      ],
      rules: [{ geosite: 'cn', server: 'local' }],
    },
    inbounds: [
      { type: 'tun', inet4_address: '172.19.0.1/30', auto_route: true, sniff: true },
    ],
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: ['auto', ...tags] },
      { type: 'urltest', tag: 'auto', outbounds: tags, url: 'http://www.gstatic.com/generate_204', interval: '3m' },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
    ],
    route: {
      rules: [
        { geosite: 'cn', geoip: 'cn', outbound: 'direct' },
      ],
      final: 'proxy',
      auto_detect_interface: true,
    },
  };
}

// ==================== VLESS 协议处理 ====================
async function handleVLESSWebSocket(request, env) {
  const config = await getConfig(env);
  const userID = config.uuid || env.UUID;
  const proxyIP = config.proxyIP || env.PROXY_IP || '';

  if (!userID) {
    return new Response('UUID not configured', { status: 500 });
  }

  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let isDns = false;

  readableWebSocketStream.pipeTo(
    new WritableStream({
      async write(chunk, controller) {
        if (isDns) {
          return handleDNS(chunk, webSocket);
        }
        if (remoteSocketWrapper.value) {
          const writer = remoteSocketWrapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }

        const { hasError, message, addressRemote, portRemote, rawDataIndex, vlessVersion, isUDP } =
          processVlessHeader(chunk, userID);

        if (hasError) {
          throw new Error(message);
        }

        if (isUDP && portRemote !== 53) {
          throw new Error('UDP only supports DNS (port 53)');
        }

        if (isUDP && portRemote === 53) {
          isDns = true;
        }

        const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
        const rawClientData = chunk.slice(rawDataIndex);

        if (isDns) {
          return handleDNS(rawClientData, webSocket, vlessResponseHeader);
        }

        handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, proxyIP);
      },
      close() {},
      abort(reason) {},
    })
  ).catch((err) => console.log('Stream error:', err));

  return new Response(null, { status: 101, webSocket: client });
}

function makeReadableWebSocketStream(webSocket, earlyDataHeader) {
  let readableStreamCancel = false;
  
  return new ReadableStream({
    start(controller) {
      webSocket.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      webSocket.addEventListener('close', () => {
        safeCloseWebSocket(webSocket);
        if (!readableStreamCancel) controller.close();
      });
      webSocket.addEventListener('error', (err) => controller.error(err));

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocket);
    },
  });
}

function processVlessHeader(buffer, userID) {
  if (buffer.byteLength < 24) {
    return { hasError: true, message: 'Invalid data' };
  }

  const version = new Uint8Array(buffer.slice(0, 1));
  const slicedBuffer = new Uint8Array(buffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);
  
  const uuids = userID.includes(',') ? userID.split(',') : [userID];
  const isValidUser = uuids.some(uuid => slicedBufferString === uuid.trim().toLowerCase());
  
  if (!isValidUser) {
    return { hasError: true, message: 'Invalid user' };
  }

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];
  const command = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  const isUDP = command === 2;

  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `Command ${command} not supported` };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  const addressIndex = portIndex + 2;
  const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
  
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 4)).join('.');
      break;
    case 2: // Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + 16));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: `Invalid address type: ${addressType}` };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

async function handleTCPOutBound(remoteSocket, address, port, rawData, webSocket, vlessHeader, proxyIP) {
  async function connectAndWrite(addr, p) {
    const tcpSocket = connect({ hostname: addr, port: p });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    if (proxyIP) {
      const tcpSocket = await connectAndWrite(proxyIP, port);
      tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
      remoteSocketToWS(tcpSocket, webSocket, vlessHeader, null);
    }
  }

  const tcpSocket = await connectAndWrite(address, port);
  remoteSocketToWS(tcpSocket, webSocket, vlessHeader, retry);
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessHeader, retry) {
  let hasIncomingData = false;
  let header = vlessHeader;

  await remoteSocket.readable.pipeTo(
    new WritableStream({
      async write(chunk) {
        hasIncomingData = true;
        if (webSocket.readyState !== 1) return;
        if (header) {
          webSocket.send(await new Blob([header, chunk]).arrayBuffer());
          header = null;
        } else {
          webSocket.send(chunk);
        }
      },
    })
  ).catch(() => safeCloseWebSocket(webSocket));

  if (!hasIncomingData && retry) retry();
}

async function handleDNS(chunk, webSocket, header) {
  const resp = await fetch('https://cloudflare-dns.com/dns-query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message' },
    body: chunk,
  });
  const result = await resp.arrayBuffer();
  const size = new Uint8Array([(result.byteLength >> 8) & 0xff, result.byteLength & 0xff]);

  if (webSocket.readyState === 1) {
    if (header) {
      webSocket.send(await new Blob([header, size, result]).arrayBuffer());
    } else {
      webSocket.send(await new Blob([size, result]).arrayBuffer());
    }
  }
}

// ==================== 工具函数 ====================
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) {
      socket.close();
    }
  } catch (e) {}
}

function base64ToArrayBuffer(base64) {
  if (!base64) return { earlyData: null, error: null };
  try {
    const str = base64.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(str);
    const buffer = Uint8Array.from(decoded, c => c.charCodeAt(0));
    return { earlyData: buffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function stringify(arr, offset = 0) {
  const hex = [];
  for (let i = 0; i < 256; i++) hex.push((i + 0x100).toString(16).slice(1));
  return (
    hex[arr[offset]] + hex[arr[offset + 1]] + hex[arr[offset + 2]] + hex[arr[offset + 3]] + '-' +
    hex[arr[offset + 4]] + hex[arr[offset + 5]] + '-' +
    hex[arr[offset + 6]] + hex[arr[offset + 7]] + '-' +
    hex[arr[offset + 8]] + hex[arr[offset + 9]] + '-' +
    hex[arr[offset + 10]] + hex[arr[offset + 11]] + hex[arr[offset + 12]] + hex[arr[offset + 13]] + hex[arr[offset + 14]] + hex[arr[offset + 15]]
  ).toLowerCase();
}

function generateYAML(obj, indent = 0) {
  let yaml = '';
  const spaces = '  '.repeat(indent);
  
  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;
    
    if (Array.isArray(value)) {
      yaml += `${spaces}${key}:\n`;
      for (const item of value) {
        if (typeof item === 'object') {
          yaml += `${spaces}  -\n`;
          yaml += generateYAML(item, indent + 2).replace(/^/gm, '  ');
        } else {
          yaml += `${spaces}  - ${item}\n`;
        }
      }
    } else if (typeof value === 'object') {
      yaml += `${spaces}${key}:\n`;
      yaml += generateYAML(value, indent + 1);
    } else {
      yaml += `${spaces}${key}: ${value}\n`;
    }
  }
  return yaml;
}

// ==================== 页面生成 ====================
function generateHomePage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
           display: flex; justify-content: center; align-items: center; height: 100vh; 
           margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
    .container { text-align: center; color: white; }
    h1 { font-size: 3rem; margin-bottom: 1rem; }
    p { font-size: 1.2rem; opacity: 0.8; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 Welcome</h1>
    <p>The service is running normally.</p>
  </div>
</body>
</html>`;
}

function handleHomePage(env) {
  return new Response(generateHomePage(), {
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}

function generateLoginPage() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           display: flex; justify-content: center; align-items: center; height: 100vh;
           margin: 0; background: #1a1a2e; }
    .login-box { background: #16213e; padding: 40px; border-radius: 10px; box-shadow: 0 15px 35px rgba(0,0,0,0.5); }
    h2 { color: #fff; text-align: center; margin-bottom: 30px; }
    input { width: 100%; padding: 15px; margin-bottom: 20px; border: none; border-radius: 5px;
            background: #0f3460; color: #fff; font-size: 16px; }
    input::placeholder { color: #888; }
    button { width: 100%; padding: 15px; border: none; border-radius: 5px; 
             background: linear-gradient(135deg, #667eea, #764ba2); color: #fff;
             font-size: 16px; cursor: pointer; transition: transform 0.2s; }
    button:hover { transform: translateY(-2px); }
  </style>
</head>
<body>
  <div class="login-box">
    <h2>🔐 Admin Login</h2>
    <form method="GET">
      <input type="password" name="pass" placeholder="Enter password" required>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>`;
}

function generateAdminPage(config, bestIPs, url, password) {
  const saved = url.searchParams.get('saved');
  const updated = url.searchParams.get('updated');
  const count = url.searchParams.get('count');
  
  const ipList = bestIPs.ips || [];
  const updatedAt = bestIPs.updatedAt || 'Never';
  
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           margin: 0; padding: 20px; background: #0f0f1a; color: #fff; min-height: 100vh; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { text-align: center; background: linear-gradient(135deg, #667eea, #764ba2);
         -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 30px; }
    .card { background: #1a1a2e; border-radius: 10px; padding: 25px; margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3); }
    .card h3 { margin-top: 0; color: #667eea; border-bottom: 1px solid #333; padding-bottom: 10px; }
    label { display: block; margin-bottom: 8px; color: #aaa; font-size: 14px; }
    input, textarea { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #333;
                      border-radius: 5px; background: #0f0f1a; color: #fff; font-size: 14px; }
    textarea { min-height: 100px; resize: vertical; }
    .btn { padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer;
           font-size: 14px; transition: all 0.2s; margin-right: 10px; margin-bottom: 10px; }
    .btn-primary { background: linear-gradient(135deg, #667eea, #764ba2); color: #fff; }
    .btn-success { background: linear-gradient(135deg, #11998e, #38ef7d); color: #fff; }
    .btn-warning { background: linear-gradient(135deg, #f093fb, #f5576c); color: #fff; }
    .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
    .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    .alert-success { background: rgba(56, 239, 125, 0.2); border: 1px solid #38ef7d; }
    .ip-list { display: flex; flex-wrap: wrap; gap: 10px; }
    .ip-tag { background: #0f3460; padding: 5px 12px; border-radius: 15px; font-size: 12px; }
    .checkbox-wrapper { display: flex; align-items: center; margin-bottom: 15px; }
    .checkbox-wrapper input { width: auto; margin-right: 10px; }
    .info { color: #888; font-size: 12px; margin-top: -10px; margin-bottom: 15px; }
    .sub-links { background: #0f0f1a; padding: 15px; border-radius: 5px; margin-top: 15px; }
    .sub-links a { color: #667eea; text-decoration: none; display: block; margin-bottom: 8px; 
                   word-break: break-all; }
    .sub-links a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚙️ CF-VLESS Admin Panel</h1>
    
    ${saved ? '<div class="alert alert-success">✅ Configuration saved successfully!</div>' : ''}
    ${updated ? `<div class="alert alert-success">✅ Best IPs updated! Found ${count} IPs.</div>` : ''}
    
    <div class="card">
      <h3>📝 Basic Configuration</h3>
      <form method="POST" action="/admin/save?pass=${password}">
        <label>UUID (Required)</label>
        <input type="text" name="uuid" value="${config.uuid || ''}" placeholder="Enter your UUID" required>
        <p class="info">Generate UUID: Run 'uuidgen' in terminal or visit uuid.rocks</p>
        
        <label>Node Name</label>
        <input type="text" name="nodeName" value="${config.nodeName || 'CF-VLESS'}" placeholder="Node name prefix">
        
        <label>Proxy IP (Optional)</label>
        <input type="text" name="proxyIP" value="${config.proxyIP || ''}" placeholder="Fallback proxy IP">
        <p class="info">Used when direct connection fails</p>
        
        <label>Custom Best IPs (One per line)</label>
        <textarea name="customIPs" placeholder="Enter custom IPs, one per line">${config.customIPs || ''}</textarea>
        <p class="info">Leave empty to use auto-fetched IPs</p>
        
        <div class="checkbox-wrapper">
          <input type="checkbox" name="autoUpdate" id="autoUpdate" ${config.autoUpdate ? 'checked' : ''}>
          <label for="autoUpdate" style="margin-bottom:0">Enable auto-update best IPs (via Cron)</label>
        </div>
        
        <button type="submit" class="btn btn-primary">💾 Save Configuration</button>
      </form>
    </div>
    
    <div class="card">
      <h3>🌐 Best IPs Management</h3>
      <p>Last updated: <strong>${updatedAt}</strong></p>
      <div class="ip-list">
        ${ipList.map(ip => `<span class="ip-tag">${ip}</span>`).join('')}
      </div>
      <div style="margin-top: 20px;">
        <a href="/admin/update-ip?pass=${password}" class="btn btn-success">🔄 Update IPs Now</a>
        <a href="/api/best-ips" target="_blank" class="btn btn-warning">📋 View IP JSON</a>
      </div>
    </div>
    
    <div class="card">
      <h3>📡 Subscription Links</h3>
      <p>Share these links with your clients:</p>
      <div class="sub-links">
        <a href="/sub" target="_blank">📄 Base64 Subscribe: ${url.origin}/sub</a>
        <a href="/sub/clash" target="_blank">🔷 Clash Config: ${url.origin}/sub/clash</a>
        <a href="/sub/singbox" target="_blank">📦 Sing-Box Config: ${url.origin}/sub/singbox</a>
      </div>
    </div>
    
    <div class="card">
      <h3>📖 Quick Guide</h3>
      <ol style="color: #aaa; line-height: 1.8;">
        <li>Set your UUID above and save</li>
        <li>Copy subscription link to your client</li>
        <li>Best IPs will auto-update daily if Cron is configured</li>
        <li>You can also manually update IPs anytime</li>
      </ol>
    </div>
  </div>
</body>
</html>`;
}

function generateSubPage(host) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Subscription Center</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           margin: 0; padding: 20px; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
           color: #fff; min-height: 100vh; }
    .container { max-width: 600px; margin: 0 auto; }
    h1 { text-align: center; margin-bottom: 10px; }
    .subtitle { text-align: center; color: #888; margin-bottom: 40px; }
    .card { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px);
            border-radius: 15px; padding: 25px; margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.1); }
    .card h3 { margin-top: 0; display: flex; align-items: center; gap: 10px; }
    .link-box { background: #0f0f1a; padding: 15px; border-radius: 8px; margin-top: 15px;
                display: flex; align-items: center; gap: 10px; }
    .link-box input { flex: 1; background: transparent; border: none; color: #fff;
                      font-size: 14px; outline: none; }
    .copy-btn { background: linear-gradient(135deg, #667eea, #764ba2); border: none;
                color: #fff; padding: 8px 16px; border-radius: 5px; cursor: pointer;
                transition: all 0.2s; }
    .copy-btn:hover { transform: scale(1.05); }
    .icon { font-size: 24px; }
    .tips { background: rgba(102, 126, 234, 0.1); border-left: 3px solid #667eea;
            padding: 15px; border-radius: 0 8px 8px 0; margin-top: 20px; }
    .tips h4 { margin: 0 0 10px 0; color: #667eea; }
    .tips ul { margin: 0; padding-left: 20px; color: #aaa; }
    .tips li { margin-bottom: 5px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>📡 Subscription Center</h1>
    <p class="subtitle">Choose your preferred subscription format</p>
    
    <div class="card">
      <h3><span class="icon">📄</span> Universal (Base64)</h3>
      <p style="color:#888">Compatible with V2rayN, V2rayNG, Shadowrocket, etc.</p>
      <div class="link-box">
        <input type="text" value="https://${host}/sub" readonly id="link1">
        <button class="copy-btn" onclick="copyLink('link1')">Copy</button>
      </div>
    </div>
    
    <div class="card">
      <h3><span class="icon">🔷</span> Clash Meta</h3>
      <p style="color:#888">For Clash Verge, ClashX Meta, Stash, etc.</p>
      <div class="link-box">
        <input type="text" value="https://${host}/sub/clash" readonly id="link2">
        <button class="copy-btn" onclick="copyLink('link2')">Copy</button>
      </div>
    </div>
    
    <div class="card">
      <h3><span class="icon">📦</span> Sing-Box</h3>
      <p style="color:#888">For Sing-Box clients</p>
      <div class="link-box">
        <input type="text" value="https://${host}/sub/singbox" readonly id="link3">
        <button class="copy-btn" onclick="copyLink('link3')">Copy</button>
      </div>
    </div>
    
    <div class="tips">
      <h4>💡 Tips</h4>
      <ul>
        <li>Subscriptions auto-update with best Cloudflare IPs</li>
        <li>For better speed, use CF IP optimization tools</li>
        <li>Update interval: Recommended every 6-12 hours</li>
      </ul>
    </div>
  </div>
  
  <script>
    function copyLink(id) {
      const input = document.getElementById(id);
      input.select();
      document.execCommand('copy');
      const btn = input.nextElementSibling;
      const originalText = btn.textContent;
      btn.textContent = 'Copied!';
      btn.style.background = 'linear-gradient(135deg, #11998e, #38ef7d)';
      setTimeout(() => {
        btn.textContent = originalText;
        btn.style.background = 'linear-gradient(135deg, #667eea, #764ba2)';
      }, 2000);
    }
  </script>
</body>
</html>`;
}
