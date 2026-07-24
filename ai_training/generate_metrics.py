#!/usr/bin/env python3
"""
NetGuard AI - Metrics & Visualization Generator
Generates PNG images for model performance: accuracy, F1, ROC curves,
confusion matrices, score distributions, and ensemble comparison.
"""

import os
import sys
import pickle
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_curve, auc, confusion_matrix, classification_report
)

warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, 'cicsd dataset', 'archive')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'docs', 'metrics')
os.makedirs(OUTPUT_DIR, exist_ok=True)

FILES = [
    'Benign-Monday-no-metadata.parquet',
    'Botnet-Friday-no-metadata.parquet',
    'Bruteforce-Tuesday-no-metadata.parquet',
    'DDoS-Friday-no-metadata.parquet',
    'DoS-Wednesday-no-metadata.parquet',
    'Infiltration-Thursday-no-metadata.parquet',
    'Portscan-Friday-no-metadata.parquet',
    'WebAttacks-Thursday-no-metadata.parquet',
]


def load_data():
    dfs = []
    for f in FILES:
        path = os.path.join(DATA_DIR, f)
        if os.path.exists(path):
            dfs.append(pd.read_parquet(path))
    df = pd.concat(dfs, ignore_index=True)
    sample_size = min(200000, len(df))
    df = df.sample(n=sample_size, random_state=42)
    return df


def preprocess(df):
    df.columns = df.columns.str.strip()
    df = df.dropna(subset=['Label'])
    df['Label'] = df['Label'].astype(str).str.strip()
    df['Binary_Label'] = (~df['Label'].str.lower().isin(['benign', 'normal'])).astype(int)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    feature_cols = [c for c in numeric_cols if c != 'Binary_Label']
    X = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
    y = df['Binary_Label'].values
    return X, y, feature_cols


def load_model(name, path):
    try:
        with open(path, 'rb') as f:
            data = pickle.load(f)
        if isinstance(data, dict):
            return data['model'], data.get('scaler'), data.get('feature_names')
        return data, None, None
    except Exception as e:
        print(f'Could not load {name}: {e}')
        return None, None, None


def evaluate_model(name, model, scaler, X_test, y_test):
    if scaler:
        Xs = scaler.transform(X_test)
    else:
        Xs = X_test

    if name == 'isolation_forest':
        raw = model.predict(Xs)
        y_pred = (raw == -1).astype(int)
        scores = np.where(raw == -1, 0.9, 0.1)
        proba = np.column_stack([1 - scores, scores])
    else:
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(Xs)
            y_pred = (proba[:, 1] >= 0.5).astype(int)
        else:
            y_pred = model.predict(Xs).astype(int)
            proba = np.column_stack([1 - y_pred, y_pred])

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    fpr, tpr, _ = roc_curve(y_test, proba[:, 1])
    roc_auc = auc(fpr, tpr)
    cm = confusion_matrix(y_test, y_pred)
    return {
        'name': name,
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'fpr': fpr,
        'tpr': tpr,
        'auc': roc_auc,
        'cm': cm,
        'scores': proba[:, 1],
        'y_pred': y_pred,
    }


def train_fallback(X_train, X_test, y_train, y_test, feature_names):
    from xgboost import XGBClassifier
    results = {}
    for name, builder in [
        ('xgboost', lambda: XGBClassifier(objective='binary:logistic', eval_metric='logloss',
                                          max_depth=8, learning_rate=0.1, n_estimators=200,
                                          subsample=0.8, colsample_bytree=0.8, n_jobs=-1,
                                          random_state=42)),
        ('random_forest', lambda: RandomForestClassifier(n_estimators=200, max_depth=20,
                                                         min_samples_split=5, min_samples_leaf=2,
                                                         class_weight='balanced', n_jobs=-1,
                                                         random_state=42)),
        ('isolation_forest', lambda: IsolationForest(n_estimators=100, contamination=0.2,
                                                     n_jobs=-1, random_state=42)),
    ]:
        scaler = StandardScaler()
        Xtr = scaler.fit_transform(X_train)
        Xte = scaler.transform(X_test)
        model = builder()
        if name == 'isolation_forest':
            model.fit(Xtr[y_train == 0])
        else:
            model.fit(Xtr, y_train)
        results[name] = evaluate_model(name, model, scaler, X_test, y_test)
    return results


def ensemble_score(results):
    xgb = results['xgboost']['scores']
    rf = results['random_forest']['scores']
    if_ = results['isolation_forest']['scores']
    weighted = 0.5 * xgb + 0.3 * rf + 0.2 * if_
    return weighted


def plot_metrics_comparison(results, output_path):
    names = ['XGBoost', 'Random Forest', 'Isolation Forest', 'Ensemble']
    metrics = ['accuracy', 'precision', 'recall', 'f1']
    data = {m: [] for m in metrics}
    for key in ['xgboost', 'random_forest', 'isolation_forest', 'ensemble']:
        for m in metrics:
            data[m].append(results[key][m])

    x = np.arange(len(names))
    width = 0.2
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ['#1976d2', '#388e3c', '#f9a825', '#c2185b']
    for i, m in enumerate(metrics):
        ax.bar(x + i * width, data[m], width, label=m.capitalize(), color=colors[i])

    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('NetGuard AI - Model Performance Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(names)
    ax.set_ylim(0, 1.05)
    ax.legend(loc='lower right')
    ax.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f'Saved: {output_path}')


def plot_roc_curves(results, output_path):
    fig, ax = plt.subplots(figsize=(8, 8))
    colors = {'xgboost': '#1976d2', 'random_forest': '#388e3c',
              'isolation_forest': '#f57c00', 'ensemble': '#c2185b'}
    labels = {'xgboost': 'XGBoost', 'random_forest': 'Random Forest',
              'isolation_forest': 'Isolation Forest', 'ensemble': 'Ensemble'}
    for key in ['xgboost', 'random_forest', 'isolation_forest', 'ensemble']:
        ax.plot(results[key]['fpr'], results[key]['tpr'],
                color=colors[key], lw=2,
                label=f"{labels[key]} (AUC = {results[key]['auc']:.3f})")
    ax.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate', fontsize=12)
    ax.set_ylabel('True Positive Rate', fontsize=12)
    ax.set_title('ROC Curves - NetGuard AI Models', fontsize=14, fontweight='bold')
    ax.legend(loc='lower right')
    ax.grid(linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f'Saved: {output_path}')


def plot_confusion_matrices(results, y_test, output_path):
    fig, axes = plt.subplots(2, 2, figsize=(10, 9))
    axes = axes.ravel()
    keys = ['xgboost', 'random_forest', 'isolation_forest', 'ensemble']
    titles = ['XGBoost', 'Random Forest', 'Isolation Forest', 'Ensemble']
    for ax, key, title in zip(axes, keys, titles):
        cm = results[key]['cm']
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                    xticklabels=['Benign', 'Attack'], yticklabels=['Benign', 'Attack'])
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.set_xlabel('Predicted', fontsize=10)
        ax.set_ylabel('Actual', fontsize=10)
    plt.suptitle('Confusion Matrices - NetGuard AI Models', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f'Saved: {output_path}')


def plot_score_distribution(results, y_test, output_path):
    scores = results['ensemble']['scores']
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.hist(scores[y_test == 0], bins=50, alpha=0.7, label='Benign', color='#388e3c')
    ax.hist(scores[y_test == 1], bins=50, alpha=0.7, label='Attack', color='#c2185b')
    ax.axvline(0.5, color='black', linestyle='--', label='Decision threshold')
    ax.set_xlabel('Ensemble Threat Score', fontsize=12)
    ax.set_ylabel('Count', fontsize=12)
    ax.set_title('Ensemble Score Distribution', fontsize=14, fontweight='bold')
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f'Saved: {output_path}')


def plot_ensemble_weights(output_path):
    labels = ['XGBoost\n0.50', 'Random Forest\n0.30', 'Isolation Forest\n0.20']
    sizes = [0.5, 0.3, 0.2]
    colors = ['#1976d2', '#388e3c', '#f57c00']
    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.0f%%',
                                       colors=colors, startangle=90,
                                       textprops={'fontsize': 11})
    ax.set_title('NetGuard AI - Ensemble Weights', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f'Saved: {output_path}')


def main():
    print('Loading data...')
    df = load_data()
    X, y, feature_names = preprocess(df)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f'Train: {len(X_train)}, Test: {len(X_test)}')

    results = {}
    model_paths = {
        'xgboost': os.path.join(MODELS_DIR, 'xgboost', 'models', 'binary_ids_model.pkl'),
        'random_forest': os.path.join(MODELS_DIR, 'random_forest', 'models', 'random_forest_binary_ids.pkl'),
        'isolation_forest': os.path.join(MODELS_DIR, 'isolation_forest', 'models', 'isolation_forest_model.pkl'),
    }

    all_loaded = True
    for name, path in model_paths.items():
        model, scaler, _ = load_model(name, path)
        if model is None:
            all_loaded = False
            break
        results[name] = evaluate_model(name, model, scaler, X_test, y_test)

    if not all_loaded:
        print('Falling back to training models for metrics...')
        results = train_fallback(X_train, X_test, y_train, y_test, feature_names)

    # Ensemble
    ens_scores = ensemble_score(results)
    ens_pred = (ens_scores >= 0.5).astype(int)
    ens_fpr, ens_tpr, _ = roc_curve(y_test, ens_scores)
    results['ensemble'] = {
        'name': 'ensemble',
        'accuracy': accuracy_score(y_test, ens_pred),
        'precision': precision_score(y_test, ens_pred, zero_division=0),
        'recall': recall_score(y_test, ens_pred, zero_division=0),
        'f1': f1_score(y_test, ens_pred, zero_division=0),
        'fpr': ens_fpr,
        'tpr': ens_tpr,
        'auc': auc(ens_fpr, ens_tpr),
        'cm': confusion_matrix(y_test, ens_pred),
        'scores': ens_scores,
        'y_pred': ens_pred,
    }

    print('\nMetrics:')
    for key, r in results.items():
        print(f"{key:20s} Acc={r['accuracy']:.4f}  F1={r['f1']:.4f}  AUC={r['auc']:.4f}")

    plot_metrics_comparison(results, os.path.join(OUTPUT_DIR, 'model_comparison.png'))
    plot_roc_curves(results, os.path.join(OUTPUT_DIR, 'roc_curves.png'))
    plot_confusion_matrices(results, y_test, os.path.join(OUTPUT_DIR, 'confusion_matrices.png'))
    plot_score_distribution(results, y_test, os.path.join(OUTPUT_DIR, 'score_distribution.png'))
    plot_ensemble_weights(os.path.join(OUTPUT_DIR, 'ensemble_weights.png'))

    print(f'\nAll metric images saved to: {OUTPUT_DIR}')


if __name__ == '__main__':
    main()
