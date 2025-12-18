import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';

const CONFIG_FILE = path.join(os.homedir(), '.firewall', 'config.json');

export interface FirewallConfig {
  url?: string;
  token?: string;
  connectedAt?: string;
}

const ensureConfigDir = async (): Promise<void> => {
  const configDir = path.dirname(CONFIG_FILE);
  try {
    await fs.mkdir(configDir, { recursive: true });
  } catch (error) {
  }
};

export const readConfig = async (): Promise<FirewallConfig> => {
  try {
    await ensureConfigDir();
    const data = await fs.readFile(CONFIG_FILE, 'utf-8');
    return JSON.parse(data);
  } catch {
    return {};
  }
};

export const writeConfig = async (config: Partial<FirewallConfig>): Promise<void> => {
  await ensureConfigDir();
  
  const existingConfig = await readConfig();
  const newConfig: FirewallConfig = {
    ...existingConfig,
    ...config,
    connectedAt: config.url && config.token ? new Date().toISOString() : existingConfig.connectedAt
  };
  
  await fs.writeFile(CONFIG_FILE, JSON.stringify(newConfig, null, 2), 'utf-8');
};

export const clearConfig = async (): Promise<void> => {
  try {
    await fs.unlink(CONFIG_FILE);
  } catch {
  }
};

export const isConfigComplete = async (): Promise<boolean> => {
  const config = await readConfig();
  return !!(config.url && config.token);
};

