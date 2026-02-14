#!/usr/bin/env python3
"""
NetGuard AI - AI Processor Service with Real ML Models
Loads trained models from aitraining and analyzes live traffic
"""

import os
import sys
import json
import logging
import signal
import pickle
from datetime import datetime
from collections import defaultdict
from configparser import ConfigParser

import psycopg2
from psycopg2.extras import execute_batch
import redis
import numpy as np

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/netguard/processor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('netguard-processor')

# Model paths - use copied models in /opt/netguard/models
MODEL_BASE_PATH = '/opt/netguard/models'

class FlowTracker:
    """Track network flows and extract CICIDS2017-style features"""
    
    def __init__(self, timeout=300):
        self.flows = defaultdict(lambda: {
            'start_time': None,
            'end_time': None,
            'packets_fwd': 0,
            'packets_bwd': 0,
            'bytes_fwd': 0,
            'bytes_bwd': 0,
            'fwd_packet_lengths': [],
            'bwd_packet_lengths': [],
            'timestamps': [],
            'fwd_iat': [],
            'bwd_iat': [],
            'src_ports': set(),
            'dst_ports': set(),
            'domains': set(),
            'psh_flags_fwd': 0,
            'psh_flags_bwd': 0,
            'urg_flags_fwd': 0,
            'urg_flags_bwd': 0,
        })
        self.timeout = timeout
    
    def get_flow_key(self, packet):
        """Generate flow key (5-tuple without ports for bidirectional)"""
        src = packet.get('src_ip')
        dst = packet.get('dst_ip')
        proto = packet.get('protocol')
        sport = packet.get('src_port', 0)
        dport = packet.get('dst_port', 0)
        # Sort src/dst for bidirectional flow
        if src < dst:
            return (src, dst, sport, dport, proto)
        else:
            return (dst, src, dport, sport, proto)
    
    def update_flow(self, packet):
        """Update flow with packet info"""
        flow_key = self.get_flow_key(packet)
        flow = self.flows[flow_key]
        
        timestamp = datetime.fromisoformat(packet['timestamp'])
        packet_len = packet.get('bytes_in', 0)
        
        if flow['start_time'] is None:
            flow['start_time'] = timestamp
            flow['last_fwd_time'] = timestamp
            flow['last_bwd_time'] = timestamp
        
        flow['end_time'] = timestamp
        flow['timestamps'].append(timestamp)
        
        # Determine direction
        src_ip = packet.get('src_ip')
        if src_ip == flow_key[0]:  # Forward direction
            flow['packets_fwd'] += 1
            flow['bytes_fwd'] += packet_len
            flow['fwd_packet_lengths'].append(packet_len)
            
            # IAT calculation
            if hasattr(flow, 'last_fwd_time'):
                iat = (timestamp - flow['last_fwd_time']).total_seconds() * 1000000  # microseconds
                flow['fwd_iat'].append(iat)
            flow['last_fwd_time'] = timestamp
            
            # Flags
            if packet.get('flags'):
                if 'P' in packet['flags']:
                    flow['psh_flags_fwd'] += 1
                if 'U' in packet['flags']:
                    flow['urg_flags_fwd'] += 1
        else:  # Backward direction
            flow['packets_bwd'] += 1
            flow['bytes_bwd'] += packet_len
            flow['bwd_packet_lengths'].append(packet_len)
            
            if hasattr(flow, 'last_bwd_time'):
                iat = (timestamp - flow['last_bwd_time']).total_seconds() * 1000000
                flow['bwd_iat'].append(iat)
            flow['last_bwd_time'] = timestamp
            
            if packet.get('flags'):
                if 'P' in packet['flags']:
                    flow['psh_flags_bwd'] += 1
                if 'U' in packet['flags']:
                    flow['urg_flags_bwd'] += 1
        
        if packet.get('src_port'):
            flow['src_ports'].add(packet['src_port'])
        if packet.get('dst_port'):
            flow['dst_ports'].add(packet['dst_port'])
        if packet.get('domain') and packet['domain'] != '-':
            flow['domains'].add(packet['domain'])
        
        return flow
    
    def get_cicids_features(self, flow_key):
        """Extract CICIDS2017-style features from flow"""
        flow = self.flows[flow_key]
        
        duration = (flow['end_time'] - flow['start_time']).total_seconds() if flow['end_time'] else 0
        duration = max(duration, 0.000001)  # Avoid division by zero
        
        total_packets = flow['packets_fwd'] + flow['packets_bwd']
        total_bytes = flow['bytes_fwd'] + flow['bytes_bwd']
        
        # Packet length statistics
        fwd_lengths = flow['fwd_packet_lengths'] if flow['fwd_packet_lengths'] else [0]
        bwd_lengths = flow['bwd_packet_lengths'] if flow['bwd_packet_lengths'] else [0]
        
        features = {
            ' Destination Port': flow_key[3],  # dst_port
            ' Flow Duration': duration * 1000000,  # microseconds
            ' Total Fwd Packets': flow['packets_fwd'],
            ' Total Backward Packets': flow['packets_bwd'],
            'Total Length of Fwd Packets': flow['bytes_fwd'],
            ' Total Length of Bwd Packets': flow['bytes_bwd'],
            ' Fwd Packet Length Max': max(fwd_lengths),
            ' Fwd Packet Length Min': min(fwd_lengths),
            ' Fwd Packet Length Mean': np.mean(fwd_lengths),
            ' Fwd Packet Length Std': np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0,
            'Bwd Packet Length Max': max(bwd_lengths),
            ' Bwd Packet Length Min': min(bwd_lengths),
            ' Bwd Packet Length Mean': np.mean(bwd_lengths),
            ' Bwd Packet Length Std': np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0,
            'Flow Bytes/s': total_bytes / duration,
            ' Flow Packets/s': total_packets / duration,
        }
        
        # IAT statistics
        fwd_iat = flow['fwd_iat'] if flow['fwd_iat'] else [0]
        bwd_iat = flow['bwd_iat'] if flow['bwd_iat'] else [0]
        all_iat = fwd_iat + bwd_iat if fwd_iat or bwd_iat else [0]
        
        features.update({
            ' Flow IAT Mean': np.mean(all_iat),
            ' Flow IAT Std': np.std(all_iat) if len(all_iat) > 1 else 0,
            ' Flow IAT Max': max(all_iat),
            ' Flow IAT Min': min(all_iat),
            'Fwd IAT Total': sum(fwd_iat),
            ' Fwd IAT Mean': np.mean(fwd_iat),
            ' Fwd IAT Std': np.std(fwd_iat) if len(fwd_iat) > 1 else 0,
            ' Fwd IAT Max': max(fwd_iat),
            ' Fwd IAT Min': min(fwd_iat),
            'Bwd IAT Total': sum(bwd_iat),
            ' Bwd IAT Mean': np.mean(bwd_iat),
            ' Bwd IAT Std': np.std(bwd_iat) if len(bwd_iat) > 1 else 0,
            ' Bwd IAT Max': max(bwd_iat),
            ' Bwd IAT Min': min(bwd_iat),
        })
        
        # Flags
        features.update({
            'Fwd PSH Flags': flow['psh_flags_fwd'],
            ' Bwd PSH Flags': flow['psh_flags_bwd'],
            ' Fwd URG Flags': flow['urg_flags_fwd'],
            ' Bwd URG Flags': flow['urg_flags_bwd'],
        })
        
        return features


class MLThreatDetector:
    """Load and use trained ML models from aitraining"""
    
    def __init__(self):
        self.models = {}
        self.feature_names = None
        self.load_models()
    
    def load_models(self):
        """Load all available models"""
        model_files = {
            'xgboost': f"{MODEL_BASE_PATH}/xgboost/models/binary_ids_model.pkl",
            'random_forest': f"{MODEL_BASE_PATH}/random_forest/models/random_forest_binary_ids.pkl",
            'isolation_forest': f"{MODEL_BASE_PATH}/isolation_forest/models/isolation_forest_model.pkl",
        }
        
        for name, path in model_files.items():
            try:
                with open(path, 'rb') as f:
                    self.models[name] = pickle.load(f)
                logger.info(f"Loaded {name} model from {path}")
            except Exception as e:
                logger.warning(f"Could not load {name} model: {e}")
        
        if not self.models:
            logger.error("No models loaded! Using fallback rule-based detection.")
        else:
            logger.info(f"Successfully loaded {len(self.models)} models")
    
    def extract_features_array(self, cicids_features, model=None):
        """Convert CICIDS features dict to numpy array for model"""
        # Get expected feature count from model
        if model and hasattr(model, 'n_features_in_'):
            n_features = model.n_features_in_
        else:
            n_features = 78  # Default CICIDS feature count
        
        # Build feature array with exact count
        features = []
        feature_values = list(cicids_features.values())
        
        for i in range(n_features):
            if i < len(feature_values):
                val = feature_values[i]
            else:
                val = 0.0  # Pad with zeros if we have fewer features
            
            # Convert to Python float first
            try:
                val = float(val)
            except (TypeError, ValueError):
                val = 0.0
            
            # Handle inf/nan
            if val == float('inf') or val == float('-inf') or val != val:  # isnan check
                val = 0.0
            
            features.append(val)
        
        return np.array(features, dtype=np.float64).reshape(1, -1)
    
    def predict(self, cicids_features):
        """Run prediction using loaded models"""
        if not self.models:
            # Fallback to rule-based
            return self._rule_based_predict(cicids_features)
        
        try:
            # Ensemble prediction
            predictions = []
            
            for name, model in self.models.items():
                try:
                    # Extract features specific to this model's expected count
                    X = self.extract_features_array(cicids_features, model)
                    
                    if name == 'isolation_forest':
                        # Isolation forest returns -1 for anomaly, 1 for normal
                        pred = model.predict(X)[0]
                        score = 0.9 if pred == -1 else 0.1
                    elif name == 'xgboost':
                        # XGBoost needs DMatrix
                        try:
                            import xgboost as xgb
                            dmatrix = xgb.DMatrix(X)
                            proba = model.predict(dmatrix)[0]
                            score = float(proba)
                        except:
                            # Fallback to regular predict
                            score = float(model.predict(X)[0])
                    else:
                        # Binary classifiers (Random Forest, etc.)
                        if hasattr(model, 'predict_proba'):
                            proba = model.predict_proba(X)[0]
                            score = proba[1] if len(proba) > 1 else proba[0]
                        else:
                            score = float(model.predict(X)[0])
                    
                    predictions.append(score)
                except Exception as e:
                    logger.warning(f"{name} prediction failed: {e}")
            
            if predictions:
                # Average ensemble
                avg_score = np.mean(predictions)
                threat_type = self._classify_threat(cicids_features, avg_score)
                return avg_score, threat_type
            else:
                return self._rule_based_predict(cicids_features)
                
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return self._rule_based_predict(cicids_features)
    
    def _rule_based_predict(self, features):
        """Fallback rule-based detection"""
        threat_score = 0.0
        threat_type = 'normal'
        
        dst_port = features.get(' Destination Port', 0)
        if dst_port in [22, 23, 3389, 5900]:
            threat_score += 0.3
            threat_type = 'suspicious_port'
        
        bytes_per_sec = features.get('Flow Bytes/s', 0)
        if bytes_per_sec > 10000000:
            threat_score += 0.4
            threat_type = 'high_data_rate'
        
        return min(threat_score, 1.0), threat_type
    
    def _classify_threat(self, features, score):
        """Classify threat type based on features and score"""
        if score < 0.3:
            return 'normal'
        
        # Determine type based on feature patterns
        dst_port = features.get(' Destination Port', 0)
        packets_per_sec = features.get(' Flow Packets/s', 0)
        bytes_per_sec = features.get('Flow Bytes/s', 0)
        
        if packets_per_sec > 10000:
            return 'ddos'
        elif dst_port in [22, 23, 3389]:
            return 'brute_force'
        elif bytes_per_sec > 10000000:
            return 'data_exfiltration'
        else:
            return 'attack'


class AIProcessor:
    def __init__(self, config_path='/etc/netguard/netguard.conf'):
        self.config = ConfigParser()
        self.config.read(config_path)
        
        # Redis
        redis_host = self.config.get('redis', 'host', fallback='localhost')
        redis_port = self.config.getint('redis', 'port', fallback=6379)
        redis_db = self.config.getint('redis', 'db', fallback=0)
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db, decode_responses=False)
        self.redis_queue = 'netguard:capture'
        
        # Database
        self.db_host = self.config.get('database', 'host', fallback='localhost')
        self.db_port = self.config.getint('database', 'port', fallback=5432)
        self.db_name = self.config.get('database', 'name', fallback='netguard')
        self.db_user = self.config.get('database', 'user', fallback='netguard')
        self.db_pass = self.config.get('database', 'password', fallback='')
        
        self.db_conn = None
        self.running = False
        
        self.flow_tracker = FlowTracker()
        self.ml_detector = MLThreatDetector()
        
        self.batch = []
        self.batch_size = 50
    
    def connect_database(self):
        self.db_conn = psycopg2.connect(
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            user=self.db_user,
            password=self.db_pass
        )
        self.db_conn.autocommit = False
        logger.info("Connected to database")
    
    def store_connections(self, connections):
        if not connections:
            return
        
        cursor = self.db_conn.cursor()
        
        query = """
            INSERT INTO connections 
            (time, src_ip, src_port, dst_ip, dst_port, domain, protocol, 
             bytes_in, bytes_out, duration, threat_score, threat_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        
        for conn in connections:
            # Convert numpy types to Python native types
            duration = conn.get('duration', 0)
            if isinstance(duration, (np.floating, np.integer)):
                duration = float(duration)
            
            threat_score = conn.get('threat_score', 0)
            if isinstance(threat_score, (np.floating, np.integer)):
                threat_score = float(threat_score)
            
            bytes_in = conn.get('bytes_in', 0)
            if isinstance(bytes_in, (np.floating, np.integer)):
                bytes_in = int(bytes_in)
            
            bytes_out = conn.get('bytes_out', 0)
            if isinstance(bytes_out, (np.floating, np.integer)):
                bytes_out = int(bytes_out)
            
            cursor.execute(query, (
                datetime.fromisoformat(conn['timestamp']),
                conn['src_ip'],
                conn.get('src_port'),
                conn['dst_ip'],
                conn.get('dst_port'),
                conn.get('domain', '-'),
                conn['protocol'],
                bytes_in,
                bytes_out,
                duration,
                threat_score,
                conn.get('threat_type', 'normal'),
            ))
            
            connection_id = cursor.fetchone()[0]
            
            # Generate alert for high/critical threats
            threat_score = conn.get('threat_score', 0)
            if threat_score >= 0.7:  # High/Critical
                self.generate_alert(conn, connection_id, cursor)
        
        self.db_conn.commit()
        cursor.close()
        
        logger.debug(f"Stored {len(connections)} connections")
    
    def generate_alert(self, conn, connection_id, cursor):
        """Generate alert for high/critical threats"""
        threat_score = conn.get('threat_score', 0)
        threat_type = conn.get('threat_type', 'attack')
        
        # Determine severity
        if threat_score >= 0.9:
            severity = 'critical'
        elif threat_score >= 0.7:
            severity = 'high'
        else:
            severity = 'medium'
        
        # Create alert message
        alert_type = threat_type.upper()
        src_ip = conn.get('src_ip', 'unknown')
        dst_ip = conn.get('dst_ip', 'unknown')
        dst_port = conn.get('dst_port', 'unknown')
        
        message = f"{alert_type} detected from {src_ip} to {dst_ip}:{dst_port} (score: {threat_score:.2f})"
        
        # Insert alert
        cursor.execute("""
            INSERT INTO alerts (time, alert_type, severity, message, src_ip, dst_ip, acknowledged)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            datetime.fromisoformat(conn['timestamp']),
            alert_type,
            severity,
            message,
            src_ip,
            dst_ip,
            False
        ))
        
        # Publish to Redis for real-time notifications
        alert_data = {
            'type': 'alert',
            'severity': severity,
            'title': f'{alert_type} Detected',
            'message': message,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'threat_score': threat_score,
            'timestamp': conn['timestamp']
        }
        
        try:
            self.redis_client.publish('netguard:alerts', json.dumps(alert_data))
            
            # Send system notification for critical/high
            if severity in ['critical', 'high']:
                self.send_system_notification(alert_data)
        except Exception as e:
            logger.warning(f"Failed to publish alert: {e}")
        
        logger.info(f"Alert generated: {message}")
    
    def send_system_notification(self, alert_data):
        """Send desktop system notification"""
        try:
            import subprocess
            
            title = f"🚨 {alert_data['title']}"
            message = alert_data['message']
            
            # Try notify-send (Linux desktop notification)
            subprocess.run([
                'notify-send',
                '--urgency=critical',
                '--app-name=NetGuard AI',
                title,
                message
            ], check=False, capture_output=True)
            
            logger.info(f"System notification sent: {title}")
        except Exception as e:
            logger.debug(f"Could not send system notification: {e}")
    
    def process_packet(self, packet):
        """Process packet with ML models"""
        # Update flow tracking
        flow = self.flow_tracker.update_flow(packet)
        flow_key = self.flow_tracker.get_flow_key(packet)
        
        # Extract CICIDS2017 features
        cicids_features = self.flow_tracker.get_cicids_features(flow_key)
        
        # ML prediction
        threat_score, threat_type = self.ml_detector.predict(cicids_features)
        
        # Enrich packet
        packet['threat_score'] = threat_score
        packet['threat_type'] = threat_type
        packet['flow_duration'] = cicids_features[' Flow Duration']
        packet['cicids_features'] = cicids_features
        
        return packet
    
    def start(self):
        logger.info("Starting AI processor with ML models")
        
        self.connect_database()
        
        try:
            self.redis_client.ping()
            logger.info("Connected to Redis")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            sys.exit(1)
        
        self.running = True
        logger.info("Processor ready, waiting for packets...")
        
        try:
            while self.running:
                raw_packets = self.redis_client.brpop(self.redis_queue, timeout=1)
                
                if raw_packets:
                    _, raw_packet = raw_packets
                    try:
                        packet = json.loads(raw_packet)
                        processed = self.process_packet(packet)
                        self.batch.append(processed)
                        
                        if len(self.batch) >= self.batch_size:
                            self.store_connections(self.batch)
                            self.batch = []
                    except Exception as e:
                        logger.error(f"Error processing packet: {e}")
                
                if self.batch:
                    self.store_connections(self.batch)
                    self.batch = []
        
        except KeyboardInterrupt:
            logger.info("Processor stopped by user")
        except Exception as e:
            logger.error(f"Processor error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        logger.info("Stopping processor...")
        self.running = False
        
        if self.batch:
            self.store_connections(self.batch)
        
        if self.db_conn:
            self.db_conn.close()
        
        logger.info("Processor stopped")

def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}")
    processor.stop()
    sys.exit(0)

if __name__ == '__main__':
    processor = AIProcessor()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    processor.start()
