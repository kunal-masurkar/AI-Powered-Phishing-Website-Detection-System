from flask import Flask, render_template, request, jsonify
import joblib
import os
from feature_extractor import URLFeatureExtractor
import pandas as pd

app = Flask(__name__)

# Load the trained model and feature names
model = joblib.load('models/phishing_detector.joblib')
feature_names = joblib.load('models/feature_names.joblib')

# Initialize feature extractor
feature_extractor = URLFeatureExtractor()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    try:
        # Get URL from request
        url = request.json['url']
        
        # Extract features
        features = feature_extractor.extract_features(url)
        
        # Convert features to DataFrame
        features_df = pd.DataFrame([features])
        
        # Ensure all required features are present
        for feature in feature_names:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        # Reorder columns to match training data
        features_df = features_df[feature_names]
        
        # Make prediction
        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0][1]
        
        # Calculate confidence
        confidence = (1 - probability) if prediction == 0 else probability
        
        # Determine if site is safe based on 75% threshold
        is_safe = confidence > 0.75
        
        # Prepare response
        result = {
            'is_phishing': bool(prediction),
            'probability': float(probability),
            'confidence': float(confidence),
            'is_safe': bool(is_safe),
            'features': features
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Create static directory if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
    
    app.run(debug=True) 