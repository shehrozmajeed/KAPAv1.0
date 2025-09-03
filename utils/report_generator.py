#!/usr/bin/env python3

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os
import json
from datetime import datetime

class TargetRanker:
    def __init__(self):
        self.model = None
        self.model_path = 'config/target_ranker_model.joblib'
        self.training_data_path = 'config/training_data.csv'
        self.feature_columns = [
            'open_ports_count', 'has_smb', 'has_http', 'has_rdp', 'has_sql',
            'has_ftp', 'os_windows', 'os_linux', 'port_445_open', 'port_3389_open',
            'port_21_open', 'port_22_open', 'port_80_open', 'port_443_open'
        ]
        
    def extract_features_from_scan(self, scan_data):
        """Extract meaningful features from Nmap scan data for ML prediction"""
        features = {
            'open_ports_count': len(scan_data.get('ports', [])),
            'has_smb': any('smb' in s.get('service', '').lower() or 
                          'microsoft-ds' in s.get('service', '').lower() or
                          'netbios' in s.get('service', '').lower() 
                          for s in scan_data.get('services', [])),
            'has_http': any('http' in s.get('service', '').lower() or 
                           'https' in s.get('service', '').lower() or
                           'www' in s.get('service', '').lower()
                           for s in scan_data.get('services', [])),
            'has_rdp': any('rdp' in s.get('service', '').lower() or 
                          'ms-wbt-server' in s.get('service', '').lower()
                          for s in scan_data.get('services', [])),
            'has_sql': any('sql' in s.get('service', '').lower() or 
                          'mysql' in s.get('service', '').lower() or
                          'mssql' in s.get('service', '').lower()
                          for s in scan_data.get('services', [])),
            'has_ftp': any('ftp' in s.get('service', '').lower() 
                          for s in scan_data.get('services', [])),
            'os_windows': 'windows' in scan_data.get('os_guess', '').lower(),
            'os_linux': 'linux' in scan_data.get('os_guess', '').lower(),
            'port_445_open': 445 in [p for p in scan_data.get('ports', [])],
            'port_3389_open': 3389 in [p for p in scan_data.get('ports', [])],
            'port_21_open': 21 in [p for p in scan_data.get('ports', [])],
            'port_22_open': 22 in [p for p in scan_data.get('ports', [])],
            'port_80_open': 80 in [p for p in scan_data.get('ports', [])],
            'port_443_open': 443 in [p for p in scan_data.get('ports', [])]
        }
        return features
    
    def create_training_data(self):
        """Create initial training data based on common penetration testing patterns"""
        # This is synthetic training data - in real usage, you'd collect actual data
        training_data = [
            # High-value targets (label 1)
            {'open_ports_count': 10, 'has_smb': True, 'has_http': True, 'has_rdp': True, 
             'has_sql': False, 'has_ftp': False, 'os_windows': True, 'os_linux': False,
             'port_445_open': True, 'port_3389_open': True, 'port_21_open': False,
             'port_22_open': False, 'port_80_open': True, 'port_443_open': True, 'label': 1},
            
            {'open_ports_count': 8, 'has_smb': True, 'has_http': False, 'has_rdp': True, 
             'has_sql': True, 'has_ftp': False, 'os_windows': True, 'os_linux': False,
             'port_445_open': True, 'port_3389_open': True, 'port_21_open': False,
             'port_22_open': False, 'port_80_open': False, 'port_443_open': False, 'label': 1},
            
            # Low-value targets (label 0)
            {'open_ports_count': 2, 'has_smb': False, 'has_http': False, 'has_rdp': False, 
             'has_sql': False, 'has_ftp': False, 'os_windows': False, 'os_linux': True,
             'port_445_open': False, 'port_3389_open': False, 'port_21_open': False,
             'port_22_open': True, 'port_80_open': False, 'port_443_open': False, 'label': 0},
            
            {'open_ports_count': 3, 'has_smb': False, 'has_http': True, 'has_rdp': False, 
             'has_sql': False, 'has_ftp': True, 'os_windows': False, 'os_linux': True,
             'port_445_open': False, 'port_3389_open': False, 'port_21_open': True,
             'port_22_open': True, 'port_80_open': True, 'port_443_open': False, 'label': 0}
        ]
        
        # Add more varied examples
        for _ in range(20):
            is_high_value = np.random.random() > 0.7
            training_data.append({
                'open_ports_count': np.random.randint(2, 20),
                'has_smb': is_high_value and np.random.random() > 0.3,
                'has_http': np.random.random() > 0.5,
                'has_rdp': is_high_value and np.random.random() > 0.4,
                'has_sql': np.random.random() > 0.8,
                'has_ftp': np.random.random() > 0.7,
                'os_windows': is_high_value or np.random.random() > 0.6,
                'os_linux': not is_high_value or np.random.random() > 0.4,
                'port_445_open': is_high_value and np.random.random() > 0.2,
                'port_3389_open': is_high_value and np.random.random() > 0.3,
                'port_21_open': np.random.random() > 0.8,
                'port_22_open': not is_high_value or np.random.random() > 0.5,
                'port_80_open': np.random.random() > 0.4,
                'port_443_open': np.random.random() > 0.6,
                'label': 1 if is_high_value else 0
            })
        
        df = pd.DataFrame(training_data)
        os.makedirs('config', exist_ok=True)
        df.to_csv(self.training_data_path, index=False)
        return df
    
    def train_model(self):
        """Train the Random Forest classifier"""
        # Create or load training data
        if not os.path.exists(self.training_data_path):
            print("[+] Creating initial training data...")
            df = self.create_training_data()
        else:
            df = pd.read_csv(self.training_data_path)
        
        # Prepare features and labels
        X = df[self.feature_columns]
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"[+] Model trained with accuracy: {accuracy:.2%}")
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        
        return accuracy
    
    def predict_target_value(self, features):
        """Predict if a target is high-value (1) or low-value (0)"""
        if self.model is None:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
            else:
                print("[+] Training model for first time use...")
                self.train_model()
        
        # Convert features to dataframe with correct column order
        feature_df = pd.DataFrame([features])[self.feature_columns]
        
        # Predict
        prediction = self.model.predict(feature_df)[0]
        probability = self.model.predict_proba(feature_df)[0][1]  # Probability of being high-value
        
        return prediction, probability
    
    def update_training_data(self, new_data, correct_label):
        """Update training data with new examples for continuous learning"""
        if not os.path.exists(self.training_data_path):
            self.create_training_data()
        
        df = pd.read_csv(self.training_data_path)
        
        # Add new data point
        new_data['label'] = correct_label
        new_row = pd.DataFrame([new_data])
        df = pd.concat([df, new_row], ignore_index=True)
        
        # Save updated data
        df.to_csv(self.training_data_path, index=False)
        
        # Retrain model with new data
        self.train_model()
        
        print(f"[+] Training data updated with new example (label: {correct_label})")

# Global instance
target_ranker = TargetRanker()

def extract_features_from_scan(scan_data):
    return target_ranker.extract_features_from_scan(scan_data)

def predict_target_value(features):
    return target_ranker.predict_target_value(features)

def train_model():
    return target_ranker.train_model()

def update_training_data(features, correct_label):
    return target_ranker.update_training_data(features, correct_label)

if __name__ == "__main__":
    # Test the model
    train_model()
    
    # Test prediction with sample data
    sample_scan = {
        'ports': [80, 443, 445, 3389],
        'services': [
            {'service': 'http', 'port': 80},
            {'service': 'https', 'port': 443},
            {'service': 'microsoft-ds', 'port': 445},
            {'service': 'ms-wbt-server', 'port': 3389}
        ],
        'os_guess': 'Windows Server 2019'
    }
    
    features = extract_features_from_scan(sample_scan)
    prediction, confidence = predict_target_value(features)
    
    print(f"Target prediction: {'HIGH VALUE' if prediction == 1 else 'LOW VALUE'}")
    print(f"Confidence: {confidence:.2%}")
