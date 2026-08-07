#!/bin/bash
# ==========================================
# Eyxa EDR - Docker Launcher & Tunnel Link (Bash)
# ==========================================

# 1. Start the Docker containers in the background
echo -e "\e[36mStarting Eyxa Docker containers...\e[0m"
docker-compose up -d --build

# 2. Poll the Cloudflare daemon until it negotiates a tunnel (up to 30 seconds)
echo -e "\e[90mWaiting for Cloudflare to negotiate a secure tunnel...\e[0m"
for i in {1..30}; do
    URL=$(docker logs eyxa-tunnel 2>&1 | grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' | tail -n 1)
    if [ -n "$URL" ]; then
        break
    fi
    sleep 1
done

if [ -n "$URL" ]; then
    echo ""
    echo -e "\e[32m=======================================================\e[0m"
    echo -e "\e[32m Eyxa EDR is LIVE! \e[0m"
    echo -e "\e[32m=======================================================\e[0m"
    echo -e " Dashboard URL : \e[36m$URL\e[0m"
    echo -e " Agent Backend : \e[33m$URL/api/ingest\e[0m"
    echo -e "\e[32m=======================================================\e[0m"
    
    echo -e "\n\e[90mReminder: Right-click the Eyxa Tray Icon on your agents -> 'Change Server IP' and paste just the hostname (without https://) if it changed!\e[0m"
else
    echo -e "\n\e[31mCould not extract the Cloudflare URL yet (it might still be connecting).\e[0m"
    echo -e "Run this command to check manually: \e[33mdocker logs eyxa-tunnel\e[0m"
fi
