#!/usr/bin/env python3
"""
NetGuard AI - Model Training Script
Trains XGBoost, Random Forest, and Isolation Forest models on CICIDS2017 dataset
"""

import os
import sys
import pickle
import warnings
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score

warnings.filterwarnings('ignore')

# Paths
DATA_DIR = "/home/israel/Desktop/final year project/netguaedai/cicsd dataset/archive"
MODELS_DIR = "/home/israel/Desktop/final year project/netguaedai/ai_training/models"

os.makedirs(os.path.join(MODELS_DIR, 'xgboost', 'models'), exist_ok=True)
os.makedirs(os.path.join(MODELS_DIR, 'random_forest', 'models'), exist_ok=True)
os.makedirs(os.path.join(MODELS_DIR, 'isolation_forest', 'models'), exist_ok=True)


def load_parquet_files():
    """Load all parquet files from data directory"""
    print("Loading parquet files...")
    
    files = [
        'Benign-Monday-no-metadata.parquet',
        'Botnet-Friday-no-metadata.parquet',
        'Bruteforce-Tuesday-no-metadata.parquet',
        'DDoS-Friday-no-metadata.parquet',
        'DoS-Wednesday-no-metadata.parquet',
        'Infiltration-Thursday-no-metadata.parquet',
        'Portscan-Friday-no-metadata.parquet',
        'WebAttacks-Thursday-no-metadata.parquet'
    ]
    
    dfs = []
    for f in files:
        path = os.path.join(DATA_DIR, f)
        if os.path.exists(path):
            print(f"  Loading {f}...")
            df = pd.read_parquet(path)
            dfs.append(df)
            print(f"    Rows: {len(df)}")
        else:
            print(f"  Warning: {f} not found")
    
    combined = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal combined dataset: {len(combined)} rows")
    return combined


def preprocess_data(df):
    """Preprocess the dataset"""
    print("\n=== Preprocessing Data ===")
    
    # Remove whitespace from column names
    df.columns = df.columns.str.strip()
    
    print(f"Columns: {list(df.columns)}")
    
    # Check for Label column
    if 'Label' not in df.columns:
        raise ValueError("No 'Label' column found!")
    
    # Drop rows with missing labels
    df = df.dropna(subset=['Label'])
    
    # Convert Label to binary (Benign/BENIGN = 0, everything else = 1)
    df['Label'] = df['Label'].astype(str).str.strip()
    df['Binary_Label'] = (~df['Label'].str.lower().isin(['benign', 'normal'])).astype(int)
    
    print(f"\nClass distribution:")
    print(df['Label'].value_counts())
    print(f"\nBinary distribution:")
    print(df['Binary_Label'].value_counts())
    
    # Select numeric features only
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    # Remove unwanted columns
    exclude_cols = ['Binary_Label']
    feature_cols = [c for c in numeric_cols if c not in exclude_cols]
    
    print(f"\nUsing {len(feature_cols)} features")
    
    # Handle infinity and NaN values
    X = df[feature_cols].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    
    y = df['Binary_Label'].values
    
    return X, y, feature_cols


def train_xgboost(X_train, X_test, y_train, y_test, feature_names):
    """Train XGBoost model"""
    print("\n=== Training XGBoost ===")
    
    try:
        import xgboost as xgb
    except ImportError:
        print("XGBoost not available, installing...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "xgboost", "--quiet"])
        import xgboost as xgb
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Calculate scale_pos_weight for imbalanced data
    n_benign = np.sum(y_train == 0)
    n_attack = np.sum(y_train == 1)
    scale_pos_weight = n_benign / max(n_attack, 1)
    print(f"Scale pos weight: {scale_pos_weight:.2f}")
    
    # Train model
    model = xgb.XGBClassifier(
        objective='binary:logistic',
        eval_metric='logloss',
        max_depth=8,
        learning_rate=0.1,
        n_estimators=200,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1,
        use_label_encoder=False
    )
    
    print("Training...")
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    
    # Save model
    model_path = os.path.join(MODELS_DIR, 'xgboost', 'models', 'binary_ids_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': model,
            'scaler': scaler,
            'feature_names': feature_names
        }, f)
    print(f"Saved to {model_path}")
    
    return model, scaler


def train_random_forest(X_train, X_test, y_train, y_test, feature_names):
    """Train Random Forest model"""
    print("\n=== Training Random Forest ===")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    print("Training...")
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    
    # Feature importance
    importances = dict(zip(feature_names, model.feature_importances_))
    top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:10]
    print("\nTop 10 important features:")
    for feat, imp in top_features:
        print(f"  {feat}: {imp:.4f}")
    
    # Save model
    model_path = os.path.join(MODELS_DIR, 'random_forest', 'models', 'random_forest_binary_ids.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': model,
            'scaler': scaler,
            'feature_names': feature_names
        }, f)
    print(f"Saved to {model_path}")
    
    return model, scaler


def train_isolation_forest(X_train, X_test, y_train, y_test, feature_names):
    """Train Isolation Forest for anomaly detection"""
    print("\n=== Training Isolation Forest ===")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Use only BENIGN samples for training (unsupervised)
    X_benign = X_train_scaled[y_train == 0]
    print(f"Training on {len(X_benign)} benign samples")
    
    # Train model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42,
        n_jobs=-1
    )
    
    print("Training...")
    model.fit(X_benign)
    
    # Evaluate
    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    # Convert -1 (anomaly) to 1 (attack), 1 (normal) to 0 (benign)
    y_pred_binary = (y_pred == -1).astype(int)
    
    accuracy = accuracy_score(y_test, y_pred_binary)
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred_binary, target_names=['BENIGN', 'ATTACK']))
    
    # Save model
    model_path = os.path.join(MODELS_DIR, 'isolation_forest', 'models', 'isolation_forest_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': model,
            'scaler': scaler,
            'feature_names': feature_names
        }, f)
    print(f"Saved to {model_path}")
    
    return model, scaler


def main():
    print("="*60)
    print("NetGuard AI - Model Training")
    print("="*60)
    
    # Load data (sample for faster training)
    df_full = load_parquet_files()
    
    # Sample data for faster training (max 200k rows)
    sample_size = min(200000, len(df_full))
    df = df_full.sample(n=sample_size, random_state=42)
    print(f"\nSampled {len(df)} rows for training")
    
    # Preprocess
    X, y, feature_names = preprocess_data(df)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Train models
    xgb_model, xgb_scaler = train_xgboost(X_train, X_test, y_train, y_test, feature_names)
    rf_model, rf_scaler = train_random_forest(X_train, X_test, y_train, y_test, feature_names)
    if_model, if_scaler = train_isolation_forest(X_train, X_test, y_train, y_test, feature_names)
    
    print("\n" + "="*60)
    print("Training Complete!")
    print("="*60)
    print(f"\nModels saved to:")
    print(f"  {MODELS_DIR}")
    print("\nTo install models for NetGuard:")
    print(f"  sudo mkdir -p /opt/netguard/models")
    print(f"  sudo cp -r {MODELS_DIR}/* /opt/netguard/models/")


if __name__ == '__main__':
    main()
    
