from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime

app = FastAPI(title="FMSecure Cloud C2")

# Databases (In-Memory)
connected_agents = {}
pending_commands = {} # <-- NEW: Stores commands waiting to be picked up by laptops

class HeartbeatPayload(BaseModel):
    machine_id: str
    hostname: str = "Unknown-PC"
    username: str = "Unknown"
    tier: str = "FREE"
    is_armed: bool = False

class CommandPayload(BaseModel):
    machine_id: str
    command: str

# --- API 1: THE HEARTBEAT (Agent calls this) ---
@app.post("/api/heartbeat")
async def receive_heartbeat(payload: HeartbeatPayload, request: Request):
    client_ip = request.client.host
    
    connected_agents[payload.machine_id] = {
        "hostname": payload.hostname,
        "ip_address": client_ip,
        "username": payload.username,
        "tier": payload.tier,
        "is_armed": payload.is_armed,
        "status": "ONLINE",
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # --- NEW: Check if the Admin queued a command for this laptop! ---
    issued_command = "CONTINUE"
    if payload.machine_id in pending_commands:
        issued_command = pending_commands.pop(payload.machine_id)
        print(f"[!] EXECUTING REMOTE COMMAND ON {payload.hostname}: {issued_command}")
        
    return {"status": "success", "command": issued_command}

# --- API 2: QUEUE COMMAND (Web Dashboard calls this) ---
@app.post("/api/command")
async def queue_command(payload: CommandPayload):
    pending_commands[payload.machine_id] = payload.command
    return {"status": "Command queued successfully"}

# --- WEB UI: THE ADMIN DASHBOARD ---
@app.get("/", response_class=HTMLResponse)
async def admin_dashboard():
    cards_html = ""
    for machine_id, data in connected_agents.items():
        armed_status = "🟢 ARMED" if data['is_armed'] else "🔴 DISARMED"
        
        cards_html += f"""
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div class="title">💻 {data['hostname']} <span class="badge">{data['ip_address']}</span></div>
                    <div class="meta">
                        User: {data['username']} | Tier: {data['tier']}<br>
                        Shields: {armed_status} | Last Heartbeat: {data['last_seen']}
                    </div>
                </div>
                <button onclick="sendCommand('{machine_id}', 'LOCKDOWN')" class="btn-lockdown">
                    🛑 ISOLATE HOST
                </button>
            </div>
        </div>
        """
        
    if not cards_html:
        cards_html = '<p style="color: #64748b;">Waiting for FMSecure agents to connect...</p>'

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>FMSecure Cloud Console</title>
        <style>
            body {{ background-color: #0f172a; color: #f1f5f9; font-family: 'Segoe UI', Tahoma, sans-serif; padding: 20px; }}
            .header {{ border-bottom: 2px solid #3b82f6; padding-bottom: 10px; margin-bottom: 20px; }}
            .card {{ background-color: #1e293b; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 5px solid #10b981; }}
            .title {{ font-size: 1.2em; font-weight: bold; }}
            .meta {{ color: #94a3b8; font-size: 0.9em; margin-top: 5px; }}
            .badge {{ background: #3b82f6; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; margin-left: 10px; }}
            /* New Button Styles */
            .btn-lockdown {{ background-color: #ef4444; color: white; border: none; padding: 10px 15px; border-radius: 5px; font-weight: bold; cursor: pointer; transition: 0.2s; }}
            .btn-lockdown:hover {{ background-color: #dc2626; transform: scale(1.05); }}
        </style>
        <script>
            // JavaScript to send the command API request without reloading the page
            async function sendCommand(machineId, cmd) {{
                if(confirm("⚠️ WARNING: Are you sure you want to remotely isolate this host? This will revoke all OS file permissions.")) {{
                    await fetch('/api/command', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{machine_id: machineId, command: cmd}})
                    }});
                    alert("Command queued! The host will lock down on its next heartbeat.");
                }}
            }}
            // Auto-refresh the dashboard every 10 seconds
            setTimeout(() => window.location.reload(), 10000); 
        </script>
    </head>
    <body>
        <div class="header">
            <h1>☁️ FMSecure Enterprise Fleet Management</h1>
            <p>Live Command & Control Server</p>
        </div>
        <h2>Connected Endpoints: {len(connected_agents)}</h2>
        {cards_html}
    </body>
    </html>
    """
    return html_content