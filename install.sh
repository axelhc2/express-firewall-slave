#!/bin/bash

# Script d'installation complet pour backfirewall
# - Installe la commande CLI 'firewall'
# - Installe le service systemd pour démarrage automatique

echo "=========================================="
echo "Installation de Backfirewall"
echo "=========================================="
echo ""

# Compilation du projet
echo "1. Compilation du projet..."
npm run build

if [ $? -ne 0 ]; then
    echo "ERREUR: La compilation a échoué"
    exit 1
fi

echo "✓ Compilation réussie"
echo ""

# Installation de la commande CLI
echo "2. Installation de la commande 'firewall'..."
if [ -w /usr/local/bin ]; then
    ln -sf "$(pwd)/dist/cli.js" /usr/local/bin/firewall
    chmod +x /usr/local/bin/firewall
    echo "✓ Commande 'firewall' installée dans /usr/local/bin"
elif command -v sudo &> /dev/null; then
    sudo ln -sf "$(pwd)/dist/cli.js" /usr/local/bin/firewall
    sudo chmod +x /usr/local/bin/firewall
    echo "✓ Commande 'firewall' installée dans /usr/local/bin (avec sudo)"
else
    echo "Installation dans ~/.local/bin..."
    mkdir -p ~/.local/bin
    ln -sf "$(pwd)/dist/cli.js" ~/.local/bin/firewall
    chmod +x ~/.local/bin/firewall
    echo "✓ Commande 'firewall' installée dans ~/.local/bin"
    echo "⚠ Assurez-vous que ~/.local/bin est dans votre PATH"
fi

echo ""

# Installation du service systemd
echo "3. Installation du service systemd..."
if [ ! -f "backfirewall.service" ]; then
    echo "ERREUR: Le fichier backfirewall.service est introuvable"
    exit 1
fi

if command -v sudo &> /dev/null; then
    sudo cp backfirewall.service /etc/systemd/system/backfirewall.service
    echo "✓ Fichier de service copié"
    
    echo "4. Configuration du service..."
    sudo systemctl daemon-reload
    echo "✓ systemd rechargé"
    
    sudo systemctl enable backfirewall.service
    echo "✓ Service activé au démarrage"
    
    echo ""
    echo "5. Démarrage du service..."
    sudo systemctl start backfirewall.service
    
    echo ""
    echo "6. Vérification du statut..."
    sudo systemctl status backfirewall.service --no-pager -l
else
    if [ -w /etc/systemd/system ]; then
        cp backfirewall.service /etc/systemd/system/backfirewall.service
        echo "✓ Fichier de service copié"
        
        echo "4. Configuration du service..."
        systemctl daemon-reload
        echo "✓ systemd rechargé"
        
        systemctl enable backfirewall.service
        echo "✓ Service activé au démarrage"
        
        echo ""
        echo "5. Démarrage du service..."
        systemctl start backfirewall.service
        
        echo ""
        echo "6. Vérification du statut..."
        systemctl status backfirewall.service --no-pager -l
    else
        echo "⚠ Impossible d'installer le service systemd sans sudo"
        echo "  Vous pouvez le faire manuellement plus tard"
    fi
fi

echo ""
echo "=========================================="
echo "Installation terminée avec succès!"
echo "=========================================="
echo ""
echo "Commandes disponibles:"
echo "  firewall status   - Voir l'état du firewall"
echo "  firewall start    - Démarrer le firewall"
echo "  firewall stop     - Arrêter le firewall"
echo "  firewall reboot   - Redémarrer le firewall"
echo "  firewall connect <url> <token> - Se connecter au cluster"
echo ""
echo "Gestion du service systemd:"
echo "  systemctl status backfirewall  - Voir le statut"
echo "  systemctl start backfirewall   - Démarrer le service"
echo "  systemctl stop backfirewall    - Arrêter le service"
echo "  systemctl restart backfirewall - Redémarrer le service"
echo "  journalctl -u backfirewall -f  - Voir les logs en temps réel"
echo ""
echo "Le firewall démarrera automatiquement au boot du VPS."
