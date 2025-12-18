import { promises as fs } from 'fs';
import { existsSync } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { platform } from 'os';

const execAsync = promisify(exec);

export interface IptablesLogEntry {
  timestamp: string;
  action: string;
  src: string;
  dst: string;
  dpt?: string;
  spt?: string;
  proto: string;
  raw: string;
}

export interface IptablesStats {
  totalEntries: number;
  byAction: {
    [action: string]: number;
  };
  byIP: {
    [ip: string]: {
      count: number;
      actions: { [action: string]: number };
      ports: { [port: string]: number };
    };
  };
  byPort: {
    [port: string]: {
      count: number;
      ips: { [ip: string]: number };
    };
  };
  entries: IptablesLogEntry[];
  error?: string;
  logFile?: string;
}

const getLogFile = (): string | null => {
  if (platform() === 'linux') {
    const possibleLogs = [
      '/var/log/syslog',
      '/var/log/messages',
      '/var/log/kern.log',
      '/var/log/secure'
    ];
    
    for (const logFile of possibleLogs) {
      if (existsSync(logFile)) {
        return logFile;
      }
    }
  }
  return null;
};

const parseLogLine = (line: string): IptablesLogEntry | null => {
  const iptablesPatterns = [
    /kernel:\s+IPTABLES-(DROP|REJECT|ACCEPT|LOG):/i,
    /kernel:\s+(DROP|REJECT|ACCEPT|LOG):/i,
    /IPTABLES\s+(DROP|REJECT|ACCEPT|LOG):/i,
    /iptables\s+(DROP|REJECT|ACCEPT|LOG):/i,
    /kernel:.*\s+(DROP|REJECT|ACCEPT|LOG):/i
  ];

  let action: string | null = null;
  for (const pattern of iptablesPatterns) {
    const match = line.match(pattern);
    if (match) {
      action = match[1].toUpperCase();
      break;
    }
  }

  if (!action || !line.includes('IN=') || !line.includes('SRC=')) {
    return null;
  }

  const srcMatch = line.match(/SRC=([\d.]+)/);
  const dstMatch = line.match(/DST=([\d.]+)/);
  const dptMatch = line.match(/DPT=(\d+)/);
  const sptMatch = line.match(/SPT=(\d+)/);
  const protoMatch = line.match(/PROTO=(\w+)/);
  
  const timestampPatterns = [
    /^(\w+\s+\d+\s+\d+:\d+:\d+)/,
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/,
    /(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})/,
    /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/
  ];
  
  let timestamp = new Date().toISOString();
  for (const pattern of timestampPatterns) {
    const match = line.match(pattern);
    if (match) {
      timestamp = match[1];
      break;
    }
  }

  return {
    timestamp: timestamp,
    action: action,
    src: srcMatch ? srcMatch[1] : 'unknown',
    dst: dstMatch ? dstMatch[1] : 'unknown',
    dpt: dptMatch ? dptMatch[1] : undefined,
    spt: sptMatch ? sptMatch[1] : undefined,
    proto: protoMatch ? protoMatch[1] : 'UNKNOWN',
    raw: line.trim()
  };
};

export const readIptablesLogs = async (lines?: number, actionFilter?: string): Promise<IptablesStats> => {
  const stats: IptablesStats = {
    totalEntries: 0,
    byAction: {},
    byIP: {},
    byPort: {},
    entries: []
  };

  try {
    let logContent: string;
    
    try {
      let grepPattern = '(DROP|REJECT|ACCEPT|LOG)';
      if (actionFilter && ['DROP', 'REJECT', 'ACCEPT', 'LOG'].includes(actionFilter.toUpperCase())) {
        grepPattern = actionFilter.toUpperCase();
      }
      
      const journalctlCmd = lines 
        ? `journalctl -k -n ${lines} --no-pager | grep -E "${grepPattern}.*IN=.*SRC="`
        : `journalctl -k --no-pager | grep -E "${grepPattern}.*IN=.*SRC="`;
      
      const { stdout } = await execAsync(journalctlCmd, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 });
      logContent = stdout;
      stats.logFile = 'journalctl -k';
    } catch (journalError: any) {
      const logFile = getLogFile();
      
      if (logFile) {
        try {
          if (lines) {
            const { stdout } = await execAsync(`tail -n ${lines} "${logFile}"`);
            logContent = stdout;
          } else {
            logContent = await fs.readFile(logFile, 'utf-8');
          }
          stats.logFile = logFile;
        } catch (fileError: any) {
          return {
            ...stats,
            error: `Impossible de lire les logs: ${fileError.message}`,
            logFile: logFile
          };
        }
      } else {
        return {
          ...stats,
          error: 'Aucun fichier de log trouvé et journalctl non accessible. Vérifiez les permissions ou configurez les logs iptables.',
          logFile: 'none'
        };
      }
    }

    const logLines = logContent.split('\n');
    
    for (const line of logLines) {
      if (!line.trim()) continue;
      
      const entry = parseLogLine(line);
      if (!entry) continue;

      stats.totalEntries++;
      
      if (!stats.byAction[entry.action]) {
        stats.byAction[entry.action] = 0;
      }
      stats.byAction[entry.action]++;

      if (!stats.byIP[entry.src]) {
        stats.byIP[entry.src] = {
          count: 0,
          actions: {},
          ports: {}
        };
      }
      stats.byIP[entry.src].count++;
      
      if (!stats.byIP[entry.src].actions[entry.action]) {
        stats.byIP[entry.src].actions[entry.action] = 0;
      }
      stats.byIP[entry.src].actions[entry.action]++;

      if (entry.dpt) {
        if (!stats.byIP[entry.src].ports[entry.dpt]) {
          stats.byIP[entry.src].ports[entry.dpt] = 0;
        }
        stats.byIP[entry.src].ports[entry.dpt]++;

        if (!stats.byPort[entry.dpt]) {
          stats.byPort[entry.dpt] = {
            count: 0,
            ips: {}
          };
        }
        stats.byPort[entry.dpt].count++;
        
        if (!stats.byPort[entry.dpt].ips[entry.src]) {
          stats.byPort[entry.dpt].ips[entry.src] = 0;
        }
        stats.byPort[entry.dpt].ips[entry.src]++;
      }

      stats.entries.push(entry);
    }

    return stats;
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      return {
        ...stats,
        error: `Fichier de log non trouvé`,
        logFile: stats.logFile || 'none'
      };
    }
    if (error.code === 'EACCES') {
      return {
        ...stats,
        error: `Permission refusée pour lire les logs. Essayez avec sudo ou vérifiez les permissions.`,
        logFile: stats.logFile || 'none'
      };
    }
    throw new Error(`Erreur lors de la lecture des logs: ${error.message}`);
  }
};

export const getTopBlockedIPs = async (limit: number = 10, actionFilter?: string): Promise<Array<{ ip: string; count: number; actions: { [action: string]: number } }>> => {
  const stats = await readIptablesLogs(undefined, actionFilter);
  
  const ipArray = Object.entries(stats.byIP)
    .map(([ip, data]) => ({
      ip,
      count: data.count,
      actions: data.actions
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);

  return ipArray;
};

export const getLogsByIP = async (ip: string, actionFilter?: string): Promise<IptablesLogEntry[]> => {
  const stats = await readIptablesLogs(undefined, actionFilter);
  return stats.entries.filter(entry => entry.src === ip);
};

export const getLogsByPort = async (port: string, actionFilter?: string): Promise<IptablesLogEntry[]> => {
  const stats = await readIptablesLogs(undefined, actionFilter);
  return stats.entries.filter(entry => entry.dpt === port);
};

export const getLogsByAction = async (action: string): Promise<IptablesLogEntry[]> => {
  const stats = await readIptablesLogs(undefined, action);
  return stats.entries;
};

