"""
Machine Learning Detection Service
Handles DDoS attack detection using Random Forest classifier
"""

import numpy as np
import joblib
import os
from datetime import datetime

class MLDetector:
    """ML-based DDoS attack detector"""
    
    def __init__(self, model_path=None):
        """Initialize the detector with a trained model"""
        self.model = None
        self.model_loaded = False
        self.confidence_threshold = float(os.getenv('MODEL_CONFIDENCE_THRESHOLD', 0.85))
        
        if model_path and os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                self.model_loaded = True
                print(f"✓ ML Model loaded from {model_path}")
            except Exception as e:
                print(f"✗ Failed to load model: {e}")
        else:
            print("⚠ No trained model found. Using rule-based detection.")
    
    def extract_features(self, packet_data):
        """
        Extract features from packet data for ML classification
        
        Args:
            packet_data (dict): Raw packet information
            
        Returns:
            np.array: Feature vector for classification
        """
        features = []
        
        # Flow-based features
        features.append(packet_data.get('packet_count', 0))
        features.append(packet_data.get('byte_count', 0))
        features.append(packet_data.get('packet_rate', 0))
        features.append(packet_data.get('byte_rate', 0))
        
        # Protocol features (one-hot encoded)
        protocol = packet_data.get('protocol', 'TCP')
        features.append(1 if protocol == 'TCP' else 0)
        features.append(1 if protocol == 'UDP' else 0)
        features.append(1 if protocol == 'ICMP' else 0)
        features.append(1 if protocol == 'HTTP' else 0)
        
        # Port features
        features.append(packet_data.get('src_port', 0))
        features.append(packet_data.get('dst_port', 0))
        
        # Packet size statistics
        features.append(packet_data.get('avg_packet_size', 0))
        features.append(packet_data.get('max_packet_size', 0))
        features.append(packet_data.get('min_packet_size', 0))
        
        # Flow duration
        features.append(packet_data.get('flow_duration', 0))
        
        # TCP flags (if available)
        features.append(packet_data.get('syn_count', 0))
        features.append(packet_data.get('ack_count', 0))
        features.append(packet_data.get('fin_count', 0))
        features.append(packet_data.get('rst_count', 0))
        
        # Connection features
        features.append(packet_data.get('unique_src_ips', 0))
        features.append(packet_data.get('unique_dst_ips', 0))
        
        return np.array(features).reshape(1, -1)
    
    def detect(self, packet_data):
        """
        Detect if traffic is malicious
        
        Args:
            packet_data (dict): Packet information
            
        Returns:
            dict: Detection result with attack type and confidence
        """
        # Extract features
        features = self.extract_features(packet_data)
        
        if self.model_loaded and self.model is not None:
            # ML-based detection
            try:
                prediction = self.model.predict(features)[0]
                probabilities = self.model.predict_proba(features)[0]
                confidence = max(probabilities)
                
                # Attack type mapping
                attack_types = [
                    'Benign',
                    'SYN Flood',
                    'UDP Flood',
                    'HTTP Flood',
                    'Slowloris',
                    'DNS Amplification'
                ]
                
                attack_type = attack_types[prediction] if prediction < len(attack_types) else 'Unknown'
                is_attack = prediction > 0 and confidence >= self.confidence_threshold
                
                return {
                    'is_attack': is_attack,
                    'attack_type': attack_type if is_attack else 'Benign',
                    'confidence': float(confidence),
                    'detection_method': 'ML',
                    'timestamp': datetime.utcnow()
                }
            except Exception as e:
                print(f"ML detection error: {e}")
                # Fall back to rule-based detection
                return self._rule_based_detection(packet_data)
        else:
            # Rule-based detection
            return self._rule_based_detection(packet_data)
    
    def _rule_based_detection(self, packet_data):
        """
        Fallback rule-based detection for common DDoS patterns
        
        Args:
            packet_data (dict): Packet information
            
        Returns:
            dict: Detection result
        """
        packet_rate = packet_data.get('packet_rate', 0)
        protocol = packet_data.get('protocol', 'TCP')
        syn_count = packet_data.get('syn_count', 0)
        packet_count = packet_data.get('packet_count', 0)
        avg_packet_size = packet_data.get('avg_packet_size', 0)
        
        # SYN Flood detection
        if protocol == 'TCP' and syn_count > packet_count * 0.8 and packet_rate > 1000:
            return {
                'is_attack': True,
                'attack_type': 'SYN Flood',
                'confidence': 0.9,
                'detection_method': 'Rule-based',
                'timestamp': datetime.utcnow()
            }
        
        # UDP Flood detection
        if protocol == 'UDP' and packet_rate > 5000:
            return {
                'is_attack': True,
                'attack_type': 'UDP Flood',
                'confidence': 0.85,
                'detection_method': 'Rule-based',
                'timestamp': datetime.utcnow()
            }
        
        # HTTP Flood detection
        if protocol == 'HTTP' and packet_rate > 2000:
            return {
                'is_attack': True,
                'attack_type': 'HTTP Flood',
                'confidence': 0.88,
                'detection_method': 'Rule-based',
                'timestamp': datetime.utcnow()
            }
        
        # Slowloris detection (low rate, many connections)
        if protocol == 'TCP' and packet_rate < 100 and packet_data.get('unique_dst_ips', 0) > 500:
            return {
                'is_attack': True,
                'attack_type': 'Slowloris',
                'confidence': 0.82,
                'detection_method': 'Rule-based',
                'timestamp': datetime.utcnow()
            }
        
        # DNS Amplification detection
        if protocol == 'UDP' and packet_data.get('dst_port') == 53 and avg_packet_size > 512:
            return {
                'is_attack': True,
                'attack_type': 'DNS Amplification',
                'confidence': 0.87,
                'detection_method': 'Rule-based',
                'timestamp': datetime.utcnow()
            }
        
        # No attack detected
        return {
            'is_attack': False,
            'attack_type': 'Benign',
            'confidence': 0.95,
            'detection_method': 'Rule-based',
            'timestamp': datetime.utcnow()
        }
    
    def get_severity(self, attack_type, confidence):
        """
        Determine severity level based on attack type and confidence
        
        Args:
            attack_type (str): Type of attack
            confidence (float): Detection confidence
            
        Returns:
            str: Severity level (low, medium, high, critical)
        """
        if not attack_type or attack_type == 'Benign':
            return 'low'
        
        # Critical attacks
        critical_attacks = ['SYN Flood', 'DNS Amplification']
        if attack_type in critical_attacks and confidence >= 0.9:
            return 'critical'
        
        # High severity
        high_attacks = ['UDP Flood', 'HTTP Flood']
        if attack_type in high_attacks and confidence >= 0.85:
            return 'high'
        
        # Medium severity
        if confidence >= 0.75:
            return 'medium'
        
        return 'low'