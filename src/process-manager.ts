import { spawn, exec } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';

const PID_FILE = path.join(os.tmpdir(), 'backfirewall.pid');
const STATUS_FILE = path.join(os.tmpdir(), 'backfirewall.status');

export interface FirewallStatus {
  running: boolean;
  pid?: number;
  port?: number;
  startedAt?: string;
}

export const isProcessRunning = async (pid: number): Promise<boolean> => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

export const readPid = async (): Promise<number | null> => {
  try {
    const data = await fs.readFile(PID_FILE, 'utf-8');
    const pid = parseInt(data.trim(), 10);
    if (isNaN(pid)) return null;
    return pid;
  } catch {
    return null;
  }
};

export const writePid = async (pid: number): Promise<void> => {
  await fs.writeFile(PID_FILE, pid.toString(), 'utf-8');
};

export const removePid = async (): Promise<void> => {
  try {
    await fs.unlink(PID_FILE);
  } catch {
  }
};

export const readStatus = async (): Promise<FirewallStatus | null> => {
  try {
    const data = await fs.readFile(STATUS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch {
    return null;
  }
};

export const writeStatus = async (status: FirewallStatus): Promise<void> => {
  await fs.writeFile(STATUS_FILE, JSON.stringify(status, null, 2), 'utf-8');
};

export const getStatus = async (): Promise<FirewallStatus> => {
  const savedStatus = await readStatus();
  const pid = await readPid();

  if (!pid || !savedStatus) {
    return { running: false };
  }

  const isRunning = await isProcessRunning(pid);
  
  if (!isRunning) {
    await removePid();
    await writeStatus({ running: false });
    return { running: false };
  }

  return {
    ...savedStatus,
    running: true,
    pid
  };
};

export const startServer = async (): Promise<number> => {
  return new Promise((resolve, reject) => {
    getStatus().then(async (status) => {
      if (status.running) {
        reject(new Error('Le firewall est déjà en cours d\'exécution'));
        return;
      }

      const serverProcess = spawn('node', [path.join(__dirname, 'index.js')], {
        detached: true,
        stdio: 'ignore',
        cwd: path.dirname(__dirname)
      });

      serverProcess.unref();

      if (!serverProcess.pid) {
        reject(new Error('Impossible d\'obtenir le PID du processus'));
        return;
      }

      const pid = serverProcess.pid;

      setTimeout(async () => {
        try {
          process.kill(pid, 0);
          await writePid(pid);
          
          const minPort = parseInt(process.env.MIN_PORT || '3000', 10);
          
          const status: FirewallStatus = {
            running: true,
            pid: pid,
            port: minPort,
            startedAt: new Date().toISOString()
          };
          
          await writeStatus(status);
          resolve(pid);
        } catch (error) {
          reject(new Error(`Erreur lors du démarrage: ${error}`));
        }
      }, 1000);
    });
  });
};

export const stopServer = async (): Promise<void> => {
  const status = await getStatus();
  
  if (!status.running || !status.pid) {
    throw new Error('Le firewall n\'est pas en cours d\'exécution');
  }

  try {
    process.kill(status.pid, 'SIGTERM');
    
    let attempts = 0;
    while (attempts < 10) {
      const isRunning = await isProcessRunning(status.pid);
      if (!isRunning) {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
      attempts++;
    }

    if (await isProcessRunning(status.pid)) {
      process.kill(status.pid, 'SIGKILL');
    }

    await removePid();
    await writeStatus({ running: false });
  } catch (error) {
    throw new Error(`Erreur lors de l'arrêt: ${error}`);
  }
};

export const rebootServer = async (): Promise<number> => {
  const status = await getStatus();
  
  if (status.running) {
    await stopServer();
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  return await startServer();
};

