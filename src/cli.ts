#!/usr/bin/env node

import * as processManager from './process-manager';
import { execSync } from 'child_process';
import * as os from 'os';
import * as fs from 'fs';
import axios from 'axios';
import * as config from './config';

const command = process.argv[2];

const detectOS = (): string => {
  const platform = os.platform();
  
  try {
    switch (platform) {
      case 'linux':
        if (fs.existsSync('/etc/os-release')) {
          const osRelease = fs.readFileSync('/etc/os-release', 'utf-8');
          const lines = osRelease.split('\n');
          
          let name = '';
          let version = '';
          let prettyName = '';
          
          for (const line of lines) {
            if (line.startsWith('NAME=')) {
              name = line.split('=')[1].replace(/"/g, '').trim();
            } else if (line.startsWith('VERSION=')) {
              version = line.split('=')[1].replace(/"/g, '').trim();
            } else if (line.startsWith('PRETTY_NAME=')) {
              prettyName = line.split('=')[1].replace(/"/g, '').trim();
            }
          }
          
          if (prettyName) {
            return prettyName;
          } else if (name && version) {
            return `${name} ${version}`;
          } else if (name) {
            return name;
          }
        }
        
        try {
          if (fs.existsSync('/etc/debian_version')) {
            const debianVersion = fs.readFileSync('/etc/debian_version', 'utf-8').trim();
            return `Debian ${debianVersion}`;
          }
        } catch {}
        
        return 'Linux';
        
      case 'win32':
        try {
          const winVersion = execSync('wmic os get Caption /value', { encoding: 'utf-8' });
          const match = winVersion.match(/Caption=(.+)/);
          if (match && match[1]) {
            return match[1].trim();
          }
        } catch {}
        return 'Windows';
        
      case 'darwin':
        try {
          const macVersion = execSync('sw_vers -productName && sw_vers -productVersion', { encoding: 'utf-8' });
          const lines = macVersion.trim().split('\n');
          if (lines.length >= 2) {
            return `${lines[0]} ${lines[1]}`;
          }
        } catch {}
        return 'macOS';
        
      case 'freebsd':
        try {
          const freebsdVersion = execSync('freebsd-version', { encoding: 'utf-8' }).trim();
          return `FreeBSD ${freebsdVersion}`;
        } catch {}
        return 'FreeBSD';
        
      default:
        return platform.charAt(0).toUpperCase() + platform.slice(1);
    }
  } catch (error) {
    return platform.charAt(0).toUpperCase() + platform.slice(1);
  }
};

const isSystemdServiceInstalled = (): boolean => {
  try {
    execSync('systemctl is-enabled backfirewall.service > /dev/null 2>&1', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};

const systemctl = (action: string): void => {
  try {
    const output = execSync(`systemctl ${action} backfirewall.service`, { encoding: 'utf-8' });
    if (output) console.log(output.trim());
  } catch (error: any) {
    if (error.stdout) console.log(error.stdout.toString().trim());
    if (error.stderr) console.error(error.stderr.toString().trim());
  }
};

const getSystemdStatus = (): void => {
  try {
    const status = execSync('systemctl is-active backfirewall.service', { encoding: 'utf-8' }).trim();
    const isEnabled = execSync('systemctl is-enabled backfirewall.service', { encoding: 'utf-8' }).trim();
    
    console.log(`État: ${status === 'active' ? 'ACTIF' : 'INACTIF'}`);
    console.log(`Démarrage automatique: ${isEnabled === 'enabled' ? 'OUI' : 'NON'}`);
    
    systemctl('status --no-pager -l');
  } catch (error: any) {
    console.error('Erreur lors de la récupération du statut:', error.message);
  }
};

async function main() {
  try {
    switch (command) {
      case 'status':
        await handleStatus();
        break;
      
      case 'start':
        await handleStart();
        break;
      
      case 'stop':
        await handleStop();
        break;
      
      case 'reboot':
        await handleReboot();
        break;
      
      case 'connect':
        await handleConnect();
        break;
      
      default:
        console.error('Commande inconnue. Utilisez: status, start, stop, reboot, ou connect');
        process.exit(1);
    }
  } catch (error) {
    console.error(`Erreur: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

async function handleStatus() {
  if (isSystemdServiceInstalled()) {
    getSystemdStatus();
  } else {
    const status = await processManager.getStatus();
    
    if (status.running) {
      console.log('État: ACTIF');
      console.log(`PID: ${status.pid}`);
      if (status.port) {
        console.log(`Port: ${status.port}`);
      }
      if (status.startedAt) {
        console.log(`Démarré le: ${new Date(status.startedAt).toLocaleString()}`);
      }
    } else {
      console.log('État: INACTIF');
    }
  }
}

async function handleStart() {
  if (isSystemdServiceInstalled()) {
    console.log('Démarrage du firewall via systemd...');
    systemctl('start');
    console.log('Firewall démarré avec succès');
  } else {
    const status = await processManager.getStatus();
    
    if (status.running) {
      console.log('Le firewall est déjà en cours d\'exécution');
      console.log(`PID: ${status.pid}`);
      process.exit(0);
    }

    console.log('Démarrage du firewall...');
    const pid = await processManager.startServer();
    console.log(`Firewall démarré avec succès (PID: ${pid})`);
  }
}

async function handleStop() {
  if (isSystemdServiceInstalled()) {
    console.log('Arrêt du firewall via systemd...');
    systemctl('stop');
    console.log('Firewall arrêté avec succès');
  } else {
    const status = await processManager.getStatus();
    
    if (!status.running) {
      console.log('Le firewall n\'est pas en cours d\'exécution');
      process.exit(0);
    }

    console.log('Arrêt du firewall...');
    await processManager.stopServer();
    console.log('Firewall arrêté avec succès');
  }
}

async function handleReboot() {
  if (isSystemdServiceInstalled()) {
    console.log('Redémarrage du firewall via systemd...');
    systemctl('restart');
    console.log('Firewall redémarré avec succès');
  } else {
    console.log('Redémarrage du firewall...');
    const pid = await processManager.rebootServer();
    console.log(`Firewall redémarré avec succès (PID: ${pid})`);
  }
}

async function handleConnect() {
  const url = process.argv[3];
  const token = process.argv[4];

  if (!url || !token) {
    console.error('Usage: firewall connect <url> <token>');
    process.exit(1);
  }

  const apiUrl = url.endsWith('/') ? `${url}api/connect` : `${url}/api/connect`;

  const hostname = os.hostname();

  const system = detectOS();

  const data = {
    hostname: hostname,
    system: system,
    token: token
  };

  try {
    console.log(`Connexion à ${apiUrl}...`);
    console.log(`Données:`, JSON.stringify(data, null, 2));
    
    const response = await axios.post(apiUrl, data, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    await config.writeConfig({
      url: url,
      token: token
    });

    console.log('Connexion réussie!');
    console.log('Configuration sauvegardée dans ~/.firewall/config.json');
    if (response.data) {
      console.log('Réponse du serveur:', JSON.stringify(response.data, null, 2));
    }
  } catch (error: any) {
    if (error.response) {
      console.error(`Erreur ${error.response.status}: ${error.response.statusText}`);
      if (error.response.data) {
        console.error('Détails:', JSON.stringify(error.response.data, null, 2));
      }
    } else if (error.request) {
      console.error('Aucune réponse du serveur. Vérifiez l\'URL et que le serveur est accessible.');
    } else {
      console.error('Erreur lors de la connexion:', error.message);
    }
    process.exit(1);
  }
}

main();

