import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { createServer } from 'net';
import { writePid, writeStatus, getStatus } from './process-manager';
import { readConfig, isConfigComplete } from './config';
import { readIptablesLogs, getTopBlockedIPs, getLogsByIP, getLogsByPort, getLogsByAction } from './iptables';
import axios from 'axios';
import { networkInterfaces, cpus, totalmem, freemem, platform, homedir } from 'os';
import { execSync, exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const FIREWALL_DEBUG = process.env.FIREWALL_DEBUG === '1' || process.env.FIREWALL_DEBUG === 'true';
const logDebug = (...args: any[]) => {
  if (FIREWALL_DEBUG) console.log(...args);
};
import { promises as fs } from 'fs';
import * as path from 'path';

dotenv.config();

const app = express();

const checkPortAvailable = (port: number): Promise<boolean> => {
  return new Promise((resolve) => {
    const server = createServer();
    
    server.listen(port, () => {
      server.once('close', () => resolve(true));
      server.close();
    });
    
    server.on('error', () => {
      resolve(false);
    });
  });
};

const findAvailablePort = async (min: number, max: number): Promise<number> => {
  for (let port = min; port <= max; port++) {
    const isAvailable = await checkPortAvailable(port);
    if (isAvailable) {
      return port;
    }
  }
  throw new Error(`Aucun port disponible entre ${min} et ${max}`);
};

const getLocalIP = (): string => {
  const interfaces = networkInterfaces();
  
  for (const name of Object.keys(interfaces)) {
    const nets = interfaces[name];
    if (nets) {
      for (const net of nets) {
        if (net.family === 'IPv4' && !net.internal) {
          return net.address;
        }
      }
    }
  }
  
  for (const name of Object.keys(interfaces)) {
    const nets = interfaces[name];
    if (nets) {
      for (const net of nets) {
        if (net.family === 'IPv4') {
          return net.address;
        }
      }
    }
  }
  
  return '127.0.0.1';
};

const getPublicIP = async (): Promise<string> => {
  try {
    const response = await axios.get('http://185.189.158.161:3000/api/ip', {
      timeout: 5000
    });
    
    if (response.data && response.data.ipv4) {
      return response.data.ipv4;
    }
  } catch (error) {
    console.warn('Impossible de récupérer l\'IP publique via l\'API, utilisation de l\'IP locale');
  }
  
  return getLocalIP();
};

const checkAuthorization = async (appUrl: string): Promise<boolean> => {
  const config = await readConfig();
  
  if (!config.url || !config.token) {
    console.error('ERREUR: Configuration manquante. Vous devez être connecté au cluster.');
    console.error('Utilisez: firewall connect <url> <token>');
    return false;
  }
  
  const ip = await getPublicIP();
  const checkUrl = config.url.endsWith('/') 
    ? `${config.url}api/connect/check` 
    : `${config.url}/api/connect/check`;
  
  try {
    console.log(`Vérification de l'autorisation auprès du cluster...`);
    console.log(`URL: ${checkUrl}`);
    console.log(`IP: ${ip}`);
    console.log(`App URL: ${appUrl}`);
    
    const response = await axios.post(checkUrl, {
      ip: ip,
      token: config.token,
      url: appUrl
    }, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    
    if (response.data && response.data.authorized === true && response.data.complete === true) {
      console.log('Autorisation confirmée par le cluster');
      if (response.data.server) {
        console.log(`Serveur: ${response.data.server.hostname || response.data.server.address}`);
      }
      return true;
    } else {
      if (response.data) {
        if (response.data.authorized !== true) {
          console.error('ERREUR: Non autorisé par le cluster');
        } else if (response.data.complete !== true) {
          console.error('ERREUR: Configuration incomplète. Le serveur n\'est pas complètement configuré.');
        }
        console.error('Réponse:', JSON.stringify(response.data, null, 2));
      } else {
        console.error('ERREUR: Réponse invalide du cluster');
      }
      return false;
    }
  } catch (error: any) {
    console.error('ERREUR: Impossible de vérifier l\'autorisation auprès du cluster');
    if (error.response) {
      console.error(`Code: ${error.response.status} - ${error.response.statusText}`);
      if (error.response.data) {
        console.error('Détails:', JSON.stringify(error.response.data, null, 2));
      }
    } else if (error.request) {
      console.error('Aucune réponse du serveur. Vérifiez que le cluster est accessible.');
    } else {
      console.error('Erreur:', error.message);
    }
    return false;
  }
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authenticateToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const config = await readConfig();
    
    if (!config.token) {
      return res.status(401).json({
        error: 'Token non configuré',
        message: 'Le serveur n\'a pas de token configuré'
      });
    }
    
    const authHeader = req.headers.authorization;
    let token: string | undefined;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else {
      token = req.headers['x-token'] as string;
    }
    
    if (!token) {
      return res.status(401).json({
        error: 'Token manquant',
        message: 'Veuillez fournir un token d\'authentification dans le header Authorization ou X-Token'
      });
    }
    
    if (token !== config.token) {
      return res.status(403).json({
        error: 'Token invalide',
        message: 'Le token fourni n\'est pas valide'
      });
    }
    
    next();
  } catch (error) {
    return res.status(500).json({
      error: 'Erreur d\'authentification',
      message: error instanceof Error ? error.message : String(error)
    });
  }
};

app.get('/', (req: Request, res: Response) => {
  res.json({ 
    message: 'Serveur Express en TypeScript fonctionne!',
    status: 'OK'
  });
});

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

const getCPUUsage = async (): Promise<{ usage: number; model: string }> => {
  const cpusInfo = cpus();
  if (cpusInfo.length === 0) {
    return { usage: 0, model: 'Unknown' };
  }
  
  try {
    const readCPUStats = async (): Promise<{ total: number; idle: number }> => {
      const stat = await fs.readFile('/proc/stat', 'utf-8');
      const cpuLine = stat.split('\n')[0];
      const parts = cpuLine.trim().split(/\s+/);
      
      const user = parseInt(parts[1]) || 0;
      const nice = parseInt(parts[2]) || 0;
      const system = parseInt(parts[3]) || 0;
      const idle = parseInt(parts[4]) || 0;
      const iowait = parseInt(parts[5]) || 0;
      const irq = parseInt(parts[6]) || 0;
      const softirq = parseInt(parts[7]) || 0;
      const steal = parseInt(parts[8]) || 0;
      
      const total = user + nice + system + idle + iowait + irq + softirq + steal;
      
      return { total, idle };
    };
    
    const stats1 = await readCPUStats();
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const stats2 = await readCPUStats();
    
    const totalDiff = stats2.total - stats1.total;
    const idleDiff = stats2.idle - stats1.idle;
    
    const usage = totalDiff > 0 ? ((totalDiff - idleDiff) / totalDiff) * 100 : 0;
    
    return {
      usage: Math.max(0, Math.min(100, Math.round(usage * 100) / 100)),
      model: cpusInfo[0].model || 'Unknown'
    };
  } catch (error) {
    return {
      usage: 0,
      model: cpusInfo[0].model || 'Unknown'
    };
  }
};

const getRAMUsage = (): { usagePercent: number; usedGB: number; totalGB: number } => {
  const total = totalmem();
  const free = freemem();
  const used = total - free;
  
  const totalGB = total / (1024 * 1024 * 1024);
  const usedGB = used / (1024 * 1024 * 1024);
  const usagePercent = (used / total) * 100;
  
  return {
    usagePercent: Math.round(usagePercent * 100) / 100,
    usedGB: Math.round(usedGB * 100) / 100,
    totalGB: Math.round(totalGB * 100) / 100
  };
};

const getDiskUsage = async (): Promise<{ usagePercent: number; usedGB: number; totalGB: number }> => {
  try {
    if (platform() === 'win32') {
      const output = execSync('wmic logicaldisk get size,freespace,caption', { encoding: 'utf-8' });
      const lines = output.split('\n').filter(line => line.trim() && !line.includes('Caption'));
      
      let totalSize = 0;
      let totalFree = 0;
      
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3) {
          const free = parseInt(parts[0]) || 0;
          const size = parseInt(parts[1]) || 0;
          totalFree += free;
          totalSize += size;
        }
      }
      
      const total = totalSize;
      const used = totalSize - totalFree;
      const totalGB = total / (1024 * 1024 * 1024);
      const usedGB = used / (1024 * 1024 * 1024);
      const usagePercent = (used / total) * 100;
      
      return {
        usagePercent: Math.round(usagePercent * 100) / 100,
        usedGB: Math.round(usedGB * 100) / 100,
        totalGB: Math.round(totalGB * 100) / 100
      };
    } else {
      const output = execSync('df -BG /', { encoding: 'utf-8' });
      const lines = output.split('\n');
      
      if (lines.length >= 2) {
        const parts = lines[1].trim().split(/\s+/);
        if (parts.length >= 4) {
          const totalGB = parseFloat(parts[1].replace('G', ''));
          const usedGB = parseFloat(parts[2].replace('G', ''));
          const usagePercent = parseFloat(parts[4].replace('%', ''));
          
          return {
            usagePercent: Math.round(usagePercent * 100) / 100,
            usedGB: Math.round(usedGB * 100) / 100,
            totalGB: Math.round(totalGB * 100) / 100
          };
        }
      }
    }
  } catch (error) {
  }
  
  return {
    usagePercent: 0,
    usedGB: 0,
    totalGB: 0
  };
};

const getNetworkUsage = async (): Promise<{ in: { mbps: number; pps: number }; out: { mbps: number; pps: number } }> => {
  if (platform() === 'win32') {
    return { 
      in: { mbps: 0, pps: 0 }, 
      out: { mbps: 0, pps: 0 } 
    };
  }
  
  try {
    const readNetworkStats = async (): Promise<{ rx: number; tx: number; rxPackets: number; txPackets: number }> => {
      const netDev = await fs.readFile('/proc/net/dev', 'utf-8');
      const lines = netDev.split('\n').slice(2);
      
      let totalRx = 0;
      let totalTx = 0;
      let totalRxPackets = 0;
      let totalTxPackets = 0;
      
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 10) {
          const interfaceName = parts[0].replace(':', '');
          
          if (interfaceName === 'lo' || 
              interfaceName.startsWith('docker') || 
              interfaceName.startsWith('veth') ||
              interfaceName.startsWith('br-') ||
              interfaceName.startsWith('virbr')) {
            continue;
          }
          
          const rx = parseInt(parts[1]) || 0;
          const tx = parseInt(parts[9]) || 0;
          const rxPackets = parseInt(parts[2]) || 0;
          const txPackets = parseInt(parts[10]) || 0;
          
          totalRx += rx;
          totalTx += tx;
          totalRxPackets += rxPackets;
          totalTxPackets += txPackets;
        }
      }
      
      return { 
        rx: totalRx, 
        tx: totalTx,
        rxPackets: totalRxPackets,
        txPackets: totalTxPackets
      };
    };
    
    const stats1 = await readNetworkStats();
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const stats2 = await readNetworkStats();
    
    const rxDiff = stats2.rx - stats1.rx;
    const txDiff = stats2.tx - stats1.tx;
    
    const rxPacketsDiff = stats2.rxPackets - stats1.rxPackets;
    const txPacketsDiff = stats2.txPackets - stats1.txPackets;
    
    const inMbps = (rxDiff * 8) / 1000000;
    const outMbps = (txDiff * 8) / 1000000;
    
    return {
      in: {
        mbps: Math.max(0, Math.round(inMbps * 100) / 100),
        pps: Math.max(0, rxPacketsDiff)
      },
      out: {
        mbps: Math.max(0, Math.round(outMbps * 100) / 100),
        pps: Math.max(0, txPacketsDiff)
      }
    };
  } catch (error) {
    return { 
      in: { mbps: 0, pps: 0 }, 
      out: { mbps: 0, pps: 0 } 
    };
  }
};

app.get('/api/status', async (req: Request, res: Response) => {
  try {
    const ip = await getPublicIP();
    const status = await getStatus();
    const config = await readConfig();
    
    const cpu = await getCPUUsage();
    const ram = getRAMUsage();
    const disk = await getDiskUsage();
    const network = await getNetworkUsage();
    
    res.json({
      ip: ip,
      up: status.running,
      connectedTo: config.url || null,
      cpu: {
        usage: cpu.usage,
        model: cpu.model
      },
      ram: {
        usagePercent: ram.usagePercent,
        usedGB: ram.usedGB,
        totalGB: ram.totalGB
      },
      disk: {
        usagePercent: disk.usagePercent,
        usedGB: disk.usedGB,
        totalGB: disk.totalGB
      },
      network: {
        in: {
          mbps: network.in.mbps,
          pps: network.in.pps
        },
        out: {
          mbps: network.out.mbps,
          pps: network.out.pps
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Erreur lors de la récupération du statut',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

app.get('/api/iptables/view', authenticateToken, async (req: Request, res: Response) => {
  try {
    const lines = req.query.lines ? parseInt(req.query.lines as string, 10) : undefined;
    const ip = req.query.ip as string | undefined;
    const port = req.query.port as string | undefined;
    const action = req.query.action as string | undefined;
    const top = req.query.top ? parseInt(req.query.top as string, 10) : undefined;

    const actionFilter = action && ['DROP', 'REJECT', 'ACCEPT', 'LOG'].includes(action.toUpperCase()) 
      ? action.toUpperCase() 
      : undefined;

    if (ip) {
      const logs = await getLogsByIP(ip, actionFilter);
      return res.json({
        success: true,
        ip: ip,
        action: actionFilter || 'ALL',
        count: logs.length,
        logs: logs
      });
    }

    if (port) {
      const logs = await getLogsByPort(port, actionFilter);
      return res.json({
        success: true,
        port: port,
        action: actionFilter || 'ALL',
        count: logs.length,
        logs: logs
      });
    }

    if (action && !top) {
      const logs = await getLogsByAction(action);
      return res.json({
        success: true,
        action: action.toUpperCase(),
        count: logs.length,
        logs: logs
      });
    }

    if (top) {
      const topIPs = await getTopBlockedIPs(top, actionFilter);
      return res.json({
        success: true,
        top: top,
        action: actionFilter || 'ALL',
        ips: topIPs
      });
    }

    const stats = await readIptablesLogs(lines, actionFilter);
    
    res.json({
      success: true,
      totalEntries: stats.totalEntries,
      byAction: stats.byAction,
      topIPs: Object.entries(stats.byIP)
        .map(([ip, data]) => ({
          ip,
          count: data.count,
          actions: data.actions,
          ports: data.ports
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 20),
      byPort: Object.entries(stats.byPort)
        .map(([port, data]) => ({
          port,
          count: data.count,
          topIPs: Object.entries(data.ips)
            .map(([ip, count]) => ({ ip, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10)
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 20),
      recentEntries: stats.entries.slice(-100),
      logFile: stats.logFile,
      error: stats.error,
      info: stats.totalEntries === 0 && !stats.error 
        ? 'Aucun log iptables trouvé. Assurez-vous d\'avoir des règles LOG dans iptables avant les règles DROP/REJECT.'
        : undefined
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la lecture des logs iptables',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

const RULES_FILE = path.join(homedir(), '.firewall', 'rules.nft');

const ensureFirewallDir = async (): Promise<void> => {
  const firewallDir = path.dirname(RULES_FILE);
  try {
    await fs.mkdir(firewallDir, { recursive: true });
  } catch (error) {
  }
};

const normalizeNftRuleLine = (line: string): string | null => {
  const trimmed = (line ?? '').trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('#')) return trimmed;
  // If we received a shell-ish line like: `... || nft add ...`, keep only the nft part.
  // Example: `list table inet X >/dev/null 2>&1 || nft add table inet X`
  if (trimmed.includes('||')) {
    const parts = trimmed.split('||');
    const rhs = parts[parts.length - 1]?.trim();
    if (rhs) return normalizeNftRuleLine(rhs);
  }
  // Accept either "nft add ..." or raw "add ..." syntax, but store raw syntax for `nft -f`.
  if (trimmed.toLowerCase().startsWith('nft ')) {
    return trimmed.slice(4).trim();
  }
  return trimmed;
};

const normalizeRuleExpr = (expr: string): string => {
  // Fix common "iptables-like" patterns people send:
  // - `... tcp accept` / `... udp accept` are not valid in nft; protocol-only match should be `ip protocol tcp/udp`.
  // Keep it minimal: only rewrite the exact invalid pattern.
  return expr
    .replace(/\s+tcp\s+accept\b/i, ' ip protocol tcp accept')
    .replace(/\s+udp\s+accept\b/i, ' ip protocol udp accept');
};

const buildNftConfigFromCommands = (lines: string[]): string | null => {
  // If user sends "add rule inet <table> <chain> ..." lines, build a proper nftables config file:
  // table inet <table> { chain input { type filter hook input priority 0; policy accept; ... } ... }
  type ChainName = 'input' | 'output' | 'forward';

  const ruleRe = /^add\s+rule\s+(inet|ip|ip6)\s+(\S+)\s+(input|output|forward)\s+(.+)$/i;

  let family: 'inet' | 'ip' | 'ip6' = 'inet';
  let table: string | null = null;
  const rulesByChain: Record<ChainName, string[]> = { input: [], output: [], forward: [] };

  for (const raw of lines) {
    const line = raw.trim();
    const m = line.match(ruleRe);
    if (!m) continue;

    const fam = (m[1].toLowerCase() as 'inet' | 'ip' | 'ip6');
    const tbl = m[2];
    const chain = (m[3].toLowerCase() as ChainName);
    const expr = m[4];

    if (!table) {
      table = tbl;
      family = fam;
    }
    if (tbl !== table) continue; // ignore mixed tables

    rulesByChain[chain].push(`    ${normalizeRuleExpr(expr)}`);
  }

  if (!table) return null;

  const chainBlock = (name: ChainName) => {
    const rules = rulesByChain[name];
    return [
      `  chain ${name} {`,
      `    type filter hook ${name} priority 0;`,
      `    policy accept;`,
      ...(rules.length ? rules : ['    # (aucune règle)']),
      `  }`
    ].join('\n');
  };

  return [
    `table ${family} ${table} {`,
    chainBlock('input'),
    chainBlock('output'),
    chainBlock('forward'),
    `}`
  ].join('\n');
};

const saveRulesToFile = async (commands: string[]): Promise<void> => {
  await ensureFirewallDir();
  
  const nftLines = commands
    .map(normalizeNftRuleLine)
    .filter((l): l is string => typeof l === 'string' && l.trim().length > 0);

  // If commands look like "add rule inet <table> <chain> ...", generate a proper config file.
  const maybeConfig = buildNftConfigFromCommands(nftLines);
  const payloadLines = maybeConfig ? [maybeConfig] : nftLines;

  const nftContent = [
    '# Règles nftables générées automatiquement',
    `# Date: ${new Date().toISOString()}`,
    '',
    ...payloadLines
  ].join('\n');
  
  await fs.writeFile(RULES_FILE, nftContent, 'utf-8');
  logDebug(`[firewall] règles sauvegardées dans ${RULES_FILE}`);
};

const flushNftRuleset = async (): Promise<{ stdout: string; stderr: string }> => {
  const cmd = 'nft flush ruleset';
  logDebug(`[firewall] flush nftables: ${cmd}`);
  const { stdout, stderr } = await execAsync(cmd, {
    timeout: 30000,
    maxBuffer: 1024 * 1024
  });
  return { stdout: stdout || '', stderr: stderr || '' };
};

const applyNftRulesFileAtomically = async (rulesFile: string): Promise<{ stdout: string; stderr: string }> => {
  const checkCmd = `nft -c -f "${rulesFile}"`;
  const applyCmd = `nft -f "${rulesFile}"`;

  logDebug(`[firewall] validation nftables: ${checkCmd}`);
  const check = await execAsync(checkCmd, {
    timeout: 300000,
    maxBuffer: 10 * 1024 * 1024
  });

  logDebug(`[firewall] application nftables: ${applyCmd}`);
  const apply = await execAsync(applyCmd, {
    timeout: 300000,
    maxBuffer: 10 * 1024 * 1024
  });

  return {
    stdout: [check.stdout, apply.stdout].filter(Boolean).join('\n'),
    stderr: [check.stderr, apply.stderr].filter(Boolean).join('\n')
  };
};

const applySavedRules = async (): Promise<void> => {
  try {
    try {
      await fs.access(RULES_FILE);
    } catch {
      logDebug('[firewall] aucun fichier de règles trouvé, démarrage sans règles nftables');
      return;
    }
    
    logDebug('[firewall] application automatique des règles nftables au démarrage');
    logDebug(`[firewall] fichier: ${RULES_FILE}`);
    
    logDebug('[firewall] suppression des règles nftables existantes');
    await flushNftRuleset();
    
    logDebug('[firewall] validation + application atomique des règles sauvegardées');
    const { stdout, stderr } = await applyNftRulesFileAtomically(RULES_FILE);
    
    // Par défaut: silencieux. En DEBUG: on expose stdout/stderr.
    if (FIREWALL_DEBUG) {
      if (stdout) logDebug('[firewall] stdout:', stdout);
      if (stderr) logDebug('[firewall] stderr:', stderr);
      logDebug('[firewall] ✓ règles nftables appliquées au démarrage');
    }
  } catch (error: any) {
    // On garde un seul log d'erreur (important), détails uniquement en DEBUG.
    console.error('[firewall] ERREUR: impossible d\'appliquer les règles nftables au démarrage:', error.message);
    if (FIREWALL_DEBUG) {
      if (error.stdout) console.error('[firewall] stdout:', error.stdout);
      if (error.stderr) console.error('[firewall] stderr:', error.stderr);
    }
  }
};

app.post('/api/firewall/rules/apply', authenticateToken, async (req: Request, res: Response) => {
  try {
    const { commands } = req.body;
    
    if (!commands) {
      return res.status(400).json({
        error: 'Commande manquante',
        message: 'Veuillez fournir des commandes dans le body de la requête (field "commands")'
      });
    }
    
    const commandsList = Array.isArray(commands) ? commands : [commands];
    
    const invalidCommands = commandsList.filter(cmd => typeof cmd !== 'string');
    if (invalidCommands.length > 0) {
      return res.status(400).json({
        error: 'Format invalide',
        message: 'Toutes les commandes doivent être des chaînes de caractères'
      });
    }
    
    const results: any[] = [];
    
    try {
      logDebug('[firewall] sauvegarde des règles dans le fichier nft');
      await saveRulesToFile(commandsList);
      results.push({
        step: 'save_rules',
        success: true,
        message: `Règles sauvegardées dans ${RULES_FILE}`
      });
    } catch (error: any) {
      results.push({
        step: 'save_rules',
        success: false,
        error: error.message
      });
      return res.status(500).json({
        error: 'Erreur lors de la sauvegarde des règles',
        message: error.message,
        results: results
      });
    }
    
    try {
      logDebug('[firewall] suppression de toutes les règles nftables');
      const flushResult = await flushNftRuleset();
      results.push({
        step: 'flush_nftables',
        success: true,
        stdout: flushResult.stdout,
        stderr: flushResult.stderr || null
      });
    } catch (error: any) {
      results.push({
        step: 'flush_nftables',
        success: false,
        error: error.message
      });
    }
    
    try {
      logDebug(`[firewall] validation + application atomique via nft: ${RULES_FILE}`);
      const { stdout, stderr } = await applyNftRulesFileAtomically(RULES_FILE);
      
      results.push({
        step: 'execute_rules',
        success: true,
        stdout: stdout,
        stderr: stderr || null,
        exitCode: 0
      });
      
      // Par défaut: pas de log. En DEBUG seulement.
      logDebug('[firewall] règles appliquées avec succès');
    } catch (error: any) {
      const exitCode = error.code || (error.signal ? -1 : 1);
      
      results.push({
        step: 'execute_rules',
        success: false,
        stdout: error.stdout || null,
        stderr: error.stderr || error.message || null,
        exitCode: exitCode,
        error: error.message
      });
      
      console.error('[firewall] erreur lors de l\'application des règles:', error.message);
      if (FIREWALL_DEBUG) {
        if (error.stdout) console.error('[firewall] stdout:', error.stdout);
        if (error.stderr) console.error('[firewall] stderr:', error.stderr);
      }
    }
    
    const allSuccess = results.every(r => r.success);
    
    res.status(allSuccess ? 200 : 207).json({
      success: allSuccess,
      message: allSuccess 
        ? 'Les règles de firewall ont été appliquées avec succès'
        : 'Certaines étapes ont échoué',
      timestamp: new Date().toISOString(),
      rulesFile: RULES_FILE,
      results: results
    });
  } catch (error) {
    res.status(500).json({
      error: 'Erreur lors de l\'application des règles',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

const startServer = async () => {
  const hasConfig = await isConfigComplete();
  if (!hasConfig) {
    console.error('ERREUR: Configuration manquante. Vous devez être connecté au cluster.');
    console.error('Utilisez: firewall connect <url> <token>');
    process.exit(1);
  }
  
  const minPort = parseInt(process.env.MIN_PORT || '3000');
  const maxPort = parseInt(process.env.MAX_PORT || '3100');
  
  try {
    const PORT = await findAvailablePort(minPort, maxPort);
    const ip = await getPublicIP();
    const appUrl = `http://${ip}:${PORT}`;
    
    const isAuthorized = await checkAuthorization(appUrl);
    if (!isAuthorized) {
      console.error('ERREUR: Non autorisé par le cluster. Démarrage annulé.');
      process.exit(1);
    }
    
    await applySavedRules();
    
    await writePid(process.pid);
    await writeStatus({
      running: true,
      pid: process.pid,
      port: PORT,
      startedAt: new Date().toISOString()
    });
    
    app.listen(PORT, () => {
      console.log(`Serveur démarré sur le port ${PORT}`);
      console.log(`URL: http://localhost:${PORT}`);
      console.log(`URL publique: ${appUrl}`);
      console.log(`PID: ${process.pid}`);
    });
  } catch (error) {
    console.error('Erreur lors du démarrage du serveur:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', async () => {
  console.log('Réception du signal SIGTERM, arrêt en cours...');
  await writeStatus({ running: false });
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('Réception du signal SIGINT, arrêt en cours...');
  await writeStatus({ running: false });
  process.exit(0);
});

startServer();

