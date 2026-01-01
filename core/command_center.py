"""
Enterprise Forensic Command Center
Orchestration platform for complex investigations
"""

import asyncio
import websockets
import json
from fastapi import FastAPI, WebSocket, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn
from typing import Dict, List, Optional, Set
import logging
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path
import threading
import queue


class ForensicCommandCenter:
    """Enterprise forensic investigation orchestration platform"""
    
    def __init__(self):
        self.app = FastAPI(title="Forensic Command Center", version="3.0.0")
        self.logger = logging.getLogger(__name__)
        self.active_investigations = {}
        self.connected_clients: Set[WebSocket] = set()
        self.task_queue = queue.Queue()
        self.db_path = "forensic_command.db"
        self._setup_database()
        self._setup_routes()
        
    def _setup_database(self):
        """Setup SQLite database for investigations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                id TEXT PRIMARY KEY,
                investigation_id TEXT,
                type TEXT NOT NULL,
                path TEXT NOT NULL,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                size INTEGER,
                acquired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id TEXT PRIMARY KEY,
                investigation_id TEXT,
                evidence_id TEXT,
                analysis_type TEXT NOT NULL,
                results TEXT NOT NULL,
                confidence_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id),
                FOREIGN KEY (evidence_id) REFERENCES evidence_items (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def _setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.get("/")
        async def dashboard():
            return HTMLResponse(self._get_dashboard_html())
            
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.connected_clients.add(websocket)
            try:
                while True:
                    data = await websocket.receive_text()
                    message = json.loads(data)
                    await self._handle_websocket_message(websocket, message)
            except:
                self.connected_clients.remove(websocket)
                
        @self.app.post("/api/investigations")
        async def create_investigation(investigation: dict, background_tasks: BackgroundTasks):
            inv_id = await self._create_investigation(investigation)
            background_tasks.add_task(self._notify_clients, {
                'type': 'investigation_created',
                'investigation_id': inv_id
            })
            return {'investigation_id': inv_id}
            
        @self.app.get("/api/investigations/{inv_id}")
        async def get_investigation(inv_id: str):
            return await self._get_investigation(inv_id)
            
        @self.app.post("/api/investigations/{inv_id}/evidence")
        async def add_evidence(inv_id: str, evidence: dict):
            evidence_id = await self._add_evidence(inv_id, evidence)
            return {'evidence_id': evidence_id}
            
        @self.app.post("/api/investigations/{inv_id}/analyze")
        async def start_analysis(inv_id: str, analysis_config: dict, background_tasks: BackgroundTasks):
            background_tasks.add_task(self._run_analysis, inv_id, analysis_config)
            return {'status': 'analysis_started'}
            
        @self.app.get("/api/dashboard/stats")
        async def get_dashboard_stats():
            return await self._get_dashboard_stats()
            
    async def _handle_websocket_message(self, websocket: WebSocket, message: dict):
        """Handle WebSocket messages from clients"""
        msg_type = message.get('type')
        
        if msg_type == 'subscribe_investigation':
            inv_id = message.get('investigation_id')
            # Subscribe client to investigation updates
            await websocket.send_text(json.dumps({
                'type': 'subscribed',
                'investigation_id': inv_id
            }))
            
        elif msg_type == 'request_status':
            stats = await self._get_dashboard_stats()
            await websocket.send_text(json.dumps({
                'type': 'status_update',
                'data': stats
            }))
            
    async def _notify_clients(self, message: dict):
        """Notify all connected clients"""
        if self.connected_clients:
            await asyncio.gather(
                *[client.send_text(json.dumps(message)) for client in self.connected_clients],
                return_exceptions=True
            )
            
    async def _create_investigation(self, investigation: dict) -> str:
        """Create new investigation"""
        import uuid
        inv_id = str(uuid.uuid4())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO investigations (id, name, status, priority, metadata)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            inv_id,
            investigation['name'],
            investigation.get('status', 'active'),
            investigation.get('priority', 'medium'),
            json.dumps(investigation.get('metadata', {}))
        ))
        
        conn.commit()
        conn.close()
        
        self.active_investigations[inv_id] = {
            'id': inv_id,
            'name': investigation['name'],
            'status': 'active',
            'created_at': datetime.now(),
            'evidence_count': 0,
            'analysis_count': 0
        }
        
        return inv_id
        
    async def _get_investigation(self, inv_id: str) -> dict:
        """Get investigation details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM investigations WHERE id = ?', (inv_id,))
        row = cursor.fetchone()
        
        if not row:
            return {'error': 'Investigation not found'}
            
        # Get evidence items
        cursor.execute('SELECT * FROM evidence_items WHERE investigation_id = ?', (inv_id,))
        evidence_rows = cursor.fetchall()
        
        # Get analysis results
        cursor.execute('SELECT * FROM analysis_results WHERE investigation_id = ?', (inv_id,))
        analysis_rows = cursor.fetchall()
        
        conn.close()
        
        return {
            'id': row[0],
            'name': row[1],
            'status': row[2],
            'priority': row[3],
            'created_at': row[4],
            'updated_at': row[5],
            'metadata': json.loads(row[6]) if row[6] else {},
            'evidence_items': len(evidence_rows),
            'analysis_results': len(analysis_rows)
        }
        
    async def _add_evidence(self, inv_id: str, evidence: dict) -> str:
        """Add evidence to investigation"""
        import uuid
        evidence_id = str(uuid.uuid4())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO evidence_items (id, investigation_id, type, path, hash_md5, hash_sha256, size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            evidence_id,
            inv_id,
            evidence['type'],
            evidence['path'],
            evidence.get('hash_md5'),
            evidence.get('hash_sha256'),
            evidence.get('size', 0)
        ))
        
        conn.commit()
        conn.close()
        
        return evidence_id
        
    async def _run_analysis(self, inv_id: str, analysis_config: dict):
        """Run analysis on investigation evidence"""
        try:
            # Simulate analysis process
            await asyncio.sleep(2)  # Simulate processing time
            
            # Store results
            import uuid
            result_id = str(uuid.uuid4())
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_results (id, investigation_id, analysis_type, results, confidence_score)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                result_id,
                inv_id,
                analysis_config['type'],
                json.dumps({'status': 'completed', 'findings': ['Sample finding 1', 'Sample finding 2']}),
                0.85
            ))
            
            conn.commit()
            conn.close()
            
            # Notify clients
            await self._notify_clients({
                'type': 'analysis_completed',
                'investigation_id': inv_id,
                'analysis_type': analysis_config['type'],
                'result_id': result_id
            })
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            await self._notify_clients({
                'type': 'analysis_failed',
                'investigation_id': inv_id,
                'error': str(e)
            })
            
    async def _get_dashboard_stats(self) -> dict:
        """Get dashboard statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Active investigations
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE status = 'active'")
        active_investigations = cursor.fetchone()[0]
        
        # Total evidence items
        cursor.execute("SELECT COUNT(*) FROM evidence_items")
        total_evidence = cursor.fetchone()[0]
        
        # Completed analyses
        cursor.execute("SELECT COUNT(*) FROM analysis_results")
        completed_analyses = cursor.fetchone()[0]
        
        # Recent activity
        cursor.execute('''
            SELECT name, created_at FROM investigations 
            ORDER BY created_at DESC LIMIT 5
        ''')
        recent_investigations = cursor.fetchall()
        
        conn.close()
        
        return {
            'active_investigations': active_investigations,
            'total_evidence': total_evidence,
            'completed_analyses': completed_analyses,
            'recent_investigations': [
                {'name': row[0], 'created_at': row[1]} for row in recent_investigations
            ],
            'system_status': 'operational',
            'connected_clients': len(self.connected_clients)
        }
        
    def _get_dashboard_html(self) -> str:
        """Get dashboard HTML"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Command Center</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .header { background: #2c3e50; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: #34495e; padding: 20px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
        .investigations { background: #2c3e50; padding: 20px; border-radius: 5px; }
        .investigation-item { background: #34495e; margin: 10px 0; padding: 15px; border-radius: 3px; }
        .status { padding: 5px 10px; border-radius: 3px; font-size: 0.8em; }
        .status.active { background: #27ae60; }
        .status.completed { background: #3498db; }
        .status.pending { background: #f39c12; }
        #log { background: #2c3e50; padding: 20px; border-radius: 5px; height: 300px; overflow-y: auto; }
        .log-entry { margin: 5px 0; padding: 5px; background: #34495e; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Forensic Command Center</h1>
        <p>Enterprise Investigation Management Platform</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-number" id="active-investigations">0</div>
            <div>Active Investigations</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="total-evidence">0</div>
            <div>Evidence Items</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="completed-analyses">0</div>
            <div>Completed Analyses</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="connected-clients">0</div>
            <div>Connected Clients</div>
        </div>
    </div>
    
    <div class="investigations">
        <h2>Recent Investigations</h2>
        <div id="recent-investigations"></div>
    </div>
    
    <div id="log">
        <h2>Real-time Activity Log</h2>
        <div id="log-entries"></div>
    </div>
    
    <script>
        const ws = new WebSocket('ws://localhost:8000/ws');
        
        ws.onopen = function() {
            console.log('Connected to Command Center');
            ws.send(JSON.stringify({type: 'request_status'}));
        };
        
        ws.onmessage = function(event) {
            const message = JSON.parse(event.data);
            handleMessage(message);
        };
        
        function handleMessage(message) {
            if (message.type === 'status_update') {
                updateDashboard(message.data);
            } else {
                addLogEntry(message);
            }
        }
        
        function updateDashboard(stats) {
            document.getElementById('active-investigations').textContent = stats.active_investigations;
            document.getElementById('total-evidence').textContent = stats.total_evidence;
            document.getElementById('completed-analyses').textContent = stats.completed_analyses;
            document.getElementById('connected-clients').textContent = stats.connected_clients;
            
            const recentDiv = document.getElementById('recent-investigations');
            recentDiv.innerHTML = stats.recent_investigations.map(inv => 
                `<div class="investigation-item">
                    <strong>${inv.name}</strong>
                    <span class="status active">Active</span>
                    <div>Created: ${inv.created_at}</div>
                </div>`
            ).join('');
        }
        
        function addLogEntry(message) {
            const logEntries = document.getElementById('log-entries');
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = `<strong>${new Date().toLocaleTimeString()}</strong> - ${message.type}: ${JSON.stringify(message)}`;
            logEntries.insertBefore(entry, logEntries.firstChild);
            
            // Keep only last 50 entries
            while (logEntries.children.length > 50) {
                logEntries.removeChild(logEntries.lastChild);
            }
        }
        
        // Request status updates every 30 seconds
        setInterval(() => {
            ws.send(JSON.stringify({type: 'request_status'}));
        }, 30000);
    </script>
</body>
</html>
        '''
        
    def start_server(self, host: str = "0.0.0.0", port: int = 8000):
        """Start the command center server"""
        self.logger.info(f"Starting Forensic Command Center on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port)


class InvestigationOrchestrator:
    """Orchestrate complex multi-stage investigations"""
    
    def __init__(self, command_center: ForensicCommandCenter):
        self.command_center = command_center
        self.logger = logging.getLogger(__name__)
        
    async def orchestrate_full_investigation(self, investigation_config: dict) -> str:
        """Orchestrate a complete investigation workflow"""
        # Create investigation
        inv_id = await self.command_center._create_investigation(investigation_config)
        
        # Define investigation stages
        stages = [
            {'name': 'Evidence Acquisition', 'function': self._stage_acquisition},
            {'name': 'Initial Analysis', 'function': self._stage_initial_analysis},
            {'name': 'Deep Analysis', 'function': self._stage_deep_analysis},
            {'name': 'Timeline Construction', 'function': self._stage_timeline},
            {'name': 'Report Generation', 'function': self._stage_reporting}
        ]
        
        # Execute stages
        for stage in stages:
            try:
                await self.command_center._notify_clients({
                    'type': 'stage_started',
                    'investigation_id': inv_id,
                    'stage': stage['name']
                })
                
                await stage['function'](inv_id, investigation_config)
                
                await self.command_center._notify_clients({
                    'type': 'stage_completed',
                    'investigation_id': inv_id,
                    'stage': stage['name']
                })
                
            except Exception as e:
                self.logger.error(f"Stage {stage['name']} failed: {e}")
                await self.command_center._notify_clients({
                    'type': 'stage_failed',
                    'investigation_id': inv_id,
                    'stage': stage['name'],
                    'error': str(e)
                })
                
        return inv_id
        
    async def _stage_acquisition(self, inv_id: str, config: dict):
        """Evidence acquisition stage"""
        await asyncio.sleep(5)  # Simulate acquisition time
        
    async def _stage_initial_analysis(self, inv_id: str, config: dict):
        """Initial analysis stage"""
        await asyncio.sleep(3)  # Simulate analysis time
        
    async def _stage_deep_analysis(self, inv_id: str, config: dict):
        """Deep analysis stage"""
        await asyncio.sleep(10)  # Simulate deep analysis time
        
    async def _stage_timeline(self, inv_id: str, config: dict):
        """Timeline construction stage"""
        await asyncio.sleep(2)  # Simulate timeline creation
        
    async def _stage_reporting(self, inv_id: str, config: dict):
        """Report generation stage"""
        await asyncio.sleep(1)  # Simulate report generation