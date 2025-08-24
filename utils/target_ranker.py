import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def create_training_data():
    """Create synthetic training data for demonstration"""
    # This is example data - in a real scenario, you'd use historical pentest data
    data = {
        'has_smb': [1, 1, 0, 1, 0, 1, 0, 1, 1, 0],
        'has_http': [1, 0, 1, 1, 0, 1, 1, 0, 1, 0],
        'has_ssh': [1, 1, 0, 1, 1, 0, 0, 1, 0, 1],
        'has_ftp': [0, 1, 0, 1, 0, 0, 1, 0, 0, 1],
        'has_rdp': [0, 0, 1, 0, 0, 1, 0, 1, 0, 0],
        'open_ports_count': [5, 3, 2, 8, 1, 4, 3, 6, 2, 3],
        'is_windows': [1, 1, 0, 1, 0, 1, 0, 1, 0, 0],
        'target_value': [1, 1, 0, 1, 0, 1, 0, 1, 0, 0]  # 1 = high value target, 0 = low value
    }
    
    return pd.DataFrame(data)

def train_model():
    """Train a simple model to predict target value"""
    df = create_training_data()
    
    X = df.drop('target_value', axis=1)
    y = df['target_value']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_train, y_train)
    
    # Save the model
    joblib.dump(model, 'config/target_ranker_model.pkl')
    
    print(f"Model trained with accuracy: {model.score(X_test, y_test):.2f}")
    return model

def predict_target_value(host_features):
    """Predict if a host is a high-value target"""
    try:
        model = joblib.load('config/target_ranker_model.pkl')
    except:
        print("Training new model...")
        model = train_model()
    
    # Ensure we have the right features in the right order
    expected_features = ['has_smb', 'has_http', 'has_ssh', 'has_ftp', 'has_rdp', 'open_ports_count', 'is_windows']
    
    # Create feature vector with correct order
    feature_vector = [host_features.get(f, 0) for f in expected_features]
    
    # Convert to DataFrame with feature names to avoid warning
    import pandas as pd
    feature_df = pd.DataFrame([feature_vector], columns=expected_features)
    
    prediction = model.predict(feature_df)
    probability = model.predict_proba(feature_df)
    
    return prediction[0], probability[0][1]

def extract_features_from_scan(scan_data):
    """Extract features from nmap scan results for ML model"""
    features = {
        'has_smb': 0,
        'has_http': 0,
        'has_ssh': 0,
        'has_ftp': 0,
        'has_rdp': 0,
        'open_ports_count': 0,
        'is_windows': 0
    }
    
    if 'services' in scan_data:
        features['open_ports_count'] = len(scan_data['ports'])
        
        for service in scan_data['services']:
            port = service['port']
            service_name = service['service'].lower()
            
            # Check for SMB
            if port in [139, 445] or 'microsoft-ds' in service_name or 'smb' in service_name:
                features['has_smb'] = 1
                
            # Check for HTTP
            if port in [80, 443, 8080, 8443] or 'http' in service_name:
                features['has_http'] = 1
                
            # Check for SSH
            if port == 22 or 'ssh' in service_name:
                features['has_ssh'] = 1
                
            # Check for FTP
            if port == 21 or 'ftp' in service_name:
                features['has_ftp'] = 1
                
            # Check for RDP
            if port == 3389 or 'rdp' in service_name:
                features['has_rdp'] = 1
    
    # Guess OS (very basic)
    os_guess = scan_data.get('os_guess', '').lower()
    if 'windows' in os_guess:
        features['is_windows'] = 1
    
    return features

if __name__ == "__main__":
    # Train and test the model
    model = train_model()
    
    # Test with example data
    test_features = {
        'has_smb': 1,
        'has_http': 1,
        'has_ssh': 0,
        'has_ftp': 0,
        'has_rdp': 1,
        'open_ports_count': 6,
        'is_windows': 1
    }
    
    prediction, probability = predict_target_value(test_features)
    print(f"Prediction: {prediction} (Probability: {probability:.2f})")
