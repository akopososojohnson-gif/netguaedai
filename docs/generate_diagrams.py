#!/usr/bin/env python3
"""
NetGuard AI - Diagram Generator
Generates PNG diagrams for documentation using Graphviz.
"""

import os
from graphviz import Digraph


DIAGRAMS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'diagrams')
os.makedirs(DIAGRAMS_DIR, exist_ok=True)


def render(dot, name):
    """Render a Graphviz Digraph to PNG and clean up the source file."""
    path = os.path.join(DIAGRAMS_DIR, name)
    dot.render(path, format='png', cleanup=True)
    print(f'Generated: {path}.png')


def architecture_diagram():
    dot = Digraph(name='architecture', format='png')
    dot.attr(rankdir='LR', dpi='200', bgcolor='white')
    dot.attr('node', shape='box', style='rounded,filled', fontname='DejaVuSans', fontsize='11')
    dot.attr('edge', fontname='DejaVuSans', fontsize='10')

    dot.node('network', 'Network Traffic\n(eth0 / wlp2s0)', fillcolor='#e3f2fd', color='#1976d2')
    dot.node('capture', 'Packet Capture\n(Scapy)', fillcolor='#fff3e0', color='#f57c00')
    dot.node('redis', 'Redis Queue\nnetguard:capture', fillcolor='#e8f5e9', color='#388e3c')
    dot.node('processor', 'AI Processor\nXGBoost / Random Forest / Isolation Forest', fillcolor='#fce4ec', color='#c2185b')
    dot.node('postgres', 'PostgreSQL / TimescaleDB\nconnections & alerts', fillcolor='#f3e5f5', color='#7b1fa2')
    dot.node('web', 'Django Web Dashboard\nPort 8765', fillcolor='#e0f2f1', color='#00796b')

    dot.edge('network', 'capture', label='raw packets')
    dot.edge('capture', 'redis', label='JSON push')
    dot.edge('redis', 'processor', label='BRPOP')
    dot.edge('processor', 'postgres', label='INSERT')
    dot.edge('postgres', 'web', label='SELECT')
    dot.edge('processor', 'web', label='Redis Pub/Sub alerts', style='dashed')

    render(dot, 'architecture')


def user_workflow_diagram():
    dot = Digraph(name='user_workflow', format='png')
    dot.attr(rankdir='TB', dpi='200', bgcolor='white')
    dot.attr('node', shape='box', style='rounded,filled', fontname='DejaVuSans', fontsize='11')
    dot.attr('edge', fontname='DejaVuSans', fontsize='10')

    dot.node('start', 'Open Browser\nhttp://localhost:8765', fillcolor='#e3f2fd', color='#1976d2')
    dot.node('login', 'Login Page\n/admin credentials', fillcolor='#fff3e0', color='#f57c00')
    dot.node('dashboard', 'Dashboard\nOverview & Statistics', fillcolor='#e8f5e9', color='#388e3c')
    dot.node('connections', 'Connections Page\nLive traffic table', fillcolor='#e0f2f1', color='#00796b')
    dot.node('threats', 'Threats Page\nHigh/critical flows', fillcolor='#ffebee', color='#c62828')
    dot.node('alerts', 'Alerts Page\nUnacknowledged events', fillcolor='#fff9c4', color='#f9a825')
    dot.node('ack', 'Acknowledge Alert\nLog user & timestamp', fillcolor='#f3e5f5', color='#7b1fa2')
    dot.node('search', 'Search Page\nHistorical query', fillcolor='#efebe9', color='#5d4037')
    dot.node('logout', 'Logout', fillcolor='#e3f2fd', color='#1976d2')

    dot.edge('start', 'login')
    dot.edge('login', 'dashboard')
    dot.edge('dashboard', 'connections')
    dot.edge('dashboard', 'threats')
    dot.edge('dashboard', 'alerts')
    dot.edge('alerts', 'ack')
    dot.edge('ack', 'alerts')
    dot.edge('dashboard', 'search')
    dot.edge('search', 'dashboard')
    dot.edge('dashboard', 'logout')

    render(dot, 'user_workflow')


def database_diagram():
    dot = Digraph(name='database_schema', format='png')
    dot.attr(rankdir='LR', dpi='200', bgcolor='white')
    dot.attr('node', shape='none', fontname='DejaVuSans', fontsize='10')
    dot.attr('edge', fontname='DejaVuSans', fontsize='10')

    connections_label = '''<
    <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
      <TR><TD BGCOLOR="#1976d2"><FONT COLOR="white"><B>connections</B></FONT></TD></TR>
      <TR><TD ALIGN="LEFT">time TIMESTAMPTZ (PK)</TD></TR>
      <TR><TD ALIGN="LEFT">id BIGSERIAL</TD></TR>
      <TR><TD ALIGN="LEFT">src_ip INET</TD></TR>
      <TR><TD ALIGN="LEFT">src_port INTEGER</TD></TR>
      <TR><TD ALIGN="LEFT">dst_ip INET</TD></TR>
      <TR><TD ALIGN="LEFT">dst_port INTEGER</TD></TR>
      <TR><TD ALIGN="LEFT">domain TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">protocol TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">bytes_in BIGINT</TD></TR>
      <TR><TD ALIGN="LEFT">bytes_out BIGINT</TD></TR>
      <TR><TD ALIGN="LEFT">duration DOUBLE PRECISION</TD></TR>
      <TR><TD ALIGN="LEFT">threat_score DOUBLE PRECISION</TD></TR>
      <TR><TD ALIGN="LEFT">threat_type TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">threat_level TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">src_country TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">src_city TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">dst_country TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">raw_packet JSONB</TD></TR>
    </TABLE>
    >'''

    alerts_label = '''<
    <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
      <TR><TD BGCOLOR="#c62828"><FONT COLOR="white"><B>alerts</B></FONT></TD></TR>
      <TR><TD ALIGN="LEFT">time TIMESTAMPTZ</TD></TR>
      <TR><TD ALIGN="LEFT">id BIGSERIAL (PK)</TD></TR>
      <TR><TD ALIGN="LEFT">alert_type TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">severity TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">threat_level TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">message TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">src_ip INET</TD></TR>
      <TR><TD ALIGN="LEFT">dst_ip INET</TD></TR>
      <TR><TD ALIGN="LEFT">acknowledged BOOLEAN</TD></TR>
      <TR><TD ALIGN="LEFT">acknowledged_by TEXT</TD></TR>
      <TR><TD ALIGN="LEFT">acknowledged_at TIMESTAMPTZ</TD></TR>
    </TABLE>
    >'''

    dot.node('connections', connections_label)
    dot.node('alerts', alerts_label)
    dot.edge('connections', 'alerts', style='dashed', label='related by time / src_ip / dst_ip', dir='none')

    render(dot, 'database_schema')


def deployment_diagram():
    dot = Digraph(name='deployment', format='png')
    dot.attr(rankdir='TB', dpi='200', bgcolor='white')
    dot.attr('node', shape='box', style='rounded,filled', fontname='DejaVuSans', fontsize='10')
    dot.attr('edge', fontname='DejaVuSans', fontsize='9')

    with dot.subgraph(name='cluster_native') as c:
        c.attr(label='Native systemd Deployment', style='filled', color='#e3f2fd', fontname='DejaVuSans', fontsize='12')
        c.node('n_capture', 'netguard-capture.service\n(root, Scapy)', fillcolor='#fff3e0', color='#f57c00')
        c.node('n_redis', 'redis-server\n(system service)', fillcolor='#e8f5e9', color='#388e3c')
        c.node('n_processor', 'netguard-processor.service\n(netguard user)', fillcolor='#fce4ec', color='#c2185b')
        c.node('n_postgres', 'postgresql\n(system service)', fillcolor='#f3e5f5', color='#7b1fa2')
        c.node('n_web', 'netguard-web.service\n(netguard user, port 8765)', fillcolor='#e0f2f1', color='#00796b')
        c.edge('n_capture', 'n_redis', label='LPUSH')
        c.edge('n_redis', 'n_processor', label='BRPOP')
        c.edge('n_processor', 'n_postgres', label='INSERT')
        c.edge('n_postgres', 'n_web', label='SELECT')

    with dot.subgraph(name='cluster_docker') as c:
        c.attr(label='Docker Compose Deployment', style='filled', color='#fff8e1', fontname='DejaVuSans', fontsize='12')
        c.node('d_capture', 'netguard-capture container\n(host network, privileged)', fillcolor='#fff3e0', color='#f57c00')
        c.node('d_redis', 'netguard-redis container', fillcolor='#e8f5e9', color='#388e3c')
        c.node('d_processor', 'netguard-processor container', fillcolor='#fce4ec', color='#c2185b')
        c.node('d_postgres', 'netguard-postgres container', fillcolor='#f3e5f5', color='#7b1fa2')
        c.node('d_web', 'netguard-web container\n(port 8765)', fillcolor='#e0f2f1', color='#00796b')
        c.edge('d_capture', 'd_redis', label='LPUSH')
        c.edge('d_redis', 'd_processor', label='BRPOP')
        c.edge('d_processor', 'd_postgres', label='INSERT')
        c.edge('d_postgres', 'd_web', label='SELECT')

    render(dot, 'deployment')


if __name__ == '__main__':
    architecture_diagram()
    user_workflow_diagram()
    database_diagram()
    deployment_diagram()
    print(f'\nAll diagrams saved to: {DIAGRAMS_DIR}')
