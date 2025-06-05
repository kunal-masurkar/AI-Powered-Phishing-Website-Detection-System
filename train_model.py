import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
import os
from feature_extractor import URLFeatureExtractor
import matplotlib.pyplot as plt
import seaborn as sns

def load_dataset(dataset_file):
    """Load the balanced dataset."""
    print(f"Loading dataset from {dataset_file}...")
    df = pd.read_csv(dataset_file)
    return df

def extract_features(df, feature_extractor):
    """Extract features for all URLs in the dataset."""
    print("Extracting features...")
    features_list = []
    total_urls = len(df['url'])
    
    for idx, url in enumerate(df['url'], 1):
        try:
            print(f"\rProcessing URL {idx}/{total_urls} ({(idx/total_urls)*100:.1f}%)", end="")
            features = feature_extractor.extract_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"\nError extracting features for {url}: {str(e)}")
            # Use default features if extraction fails
            features_list.append({
                'url_length': 0,
                'num_dots': 0,
                'num_hyphens': 0,
                'num_underscores': 0,
                'num_slashes': 0,
                'num_question_marks': 0,
                'num_equal_signs': 0,
                'num_at_symbols': 0,
                'num_suspicious_words': 0,
                'domain_length': 0,
                'tld_length': 0,
                'is_suspicious_tld': 0,
                'num_subdomains': 0,
                'has_ip_in_domain': 0,
                'has_ssl': 0,
                'ssl_expiry_days': 0,
                'domain_age_days': 0,
                'domain_expiry_days': 0,
                'num_forms': 0,
                'num_inputs': 0,
                'num_iframes': 0,
                'num_external_links': 0,
                'num_internal_links': 0
            })
    
    print("\nFeature extraction completed!")
    return pd.DataFrame(features_list)

def train_and_evaluate_models(X, y):
    """Train and evaluate multiple ML models."""
    print("\nTraining and evaluating models...")
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Initialize models
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        ),
        'XGBoost': XGBClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        ),
        'SVM': SVC(
            kernel='rbf',
            probability=True,
            random_state=42
        )
    }
    
    results = {}
    
    for name, model in models.items():
        print(f"\nTraining {name}...")
        
        # Perform cross-validation
        cv_scores = cross_val_score(model, X_train, y_train, cv=5)
        print(f"Cross-validation scores: {cv_scores}")
        print(f"Average CV score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Train the model
        model.fit(X_train, y_train)
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print(f"\n{name} Performance Metrics:")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        
        # Print classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Create confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f'{name} Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig(f'models/{name.lower().replace(" ", "_")}_confusion_matrix.png')
        plt.close()
        
        # Feature importance (for tree-based models)
        if name in ['Random Forest', 'XGBoost']:
            feature_importance = pd.DataFrame({
                'feature': X.columns,
                'importance': model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            plt.figure(figsize=(10, 6))
            sns.barplot(x='importance', y='feature', data=feature_importance.head(10))
            plt.title(f'{name} - Top 10 Most Important Features')
            plt.tight_layout()
            plt.savefig(f'models/{name.lower().replace(" ", "_")}_feature_importance.png')
            plt.close()
        
        # Save results
        results[name] = {
            'model': model,
            'metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
        }
    
    # Compare models
    metrics_df = pd.DataFrame({
        name: results[name]['metrics']
        for name in models.keys()
    }).T
    
    plt.figure(figsize=(10, 6))
    metrics_df.plot(kind='bar', rot=0)
    plt.title('Model Comparison')
    plt.ylabel('Score')
    plt.tight_layout()
    plt.savefig('models/model_comparison.png')
    plt.close()
    
    # Save the best model
    best_model_name = metrics_df['f1'].idxmax()
    best_model = results[best_model_name]['model']
    print(f"\nBest performing model: {best_model_name}")
    print(f"F1 Score: {metrics_df.loc[best_model_name, 'f1']:.4f}")
    
    return best_model, X_test, y_test

def main():
    # Create models directory if it doesn't exist
    if not os.path.exists('models'):
        os.makedirs('models')
    
    # Initialize feature extractor
    feature_extractor = URLFeatureExtractor()
    
    # Load dataset
    df = load_dataset('data/balanced_dataset.csv')
    
    # Extract features
    X = extract_features(df, feature_extractor)
    y = df['label']
    
    # Train and evaluate models
    best_model, X_test, y_test = train_and_evaluate_models(X, y)
    
    # Save best model
    print("\nSaving best model...")
    joblib.dump(best_model, 'models/phishing_detector.joblib')
    
    # Save feature names
    feature_names = X.columns.tolist()
    joblib.dump(feature_names, 'models/feature_names.joblib')
    
    print("\nModel training completed successfully!")
    print("Model saved to 'models/phishing_detector.joblib'")
    print("Visualizations saved to 'models/' directory")

if __name__ == "__main__":
    main() 