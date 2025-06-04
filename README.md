# 🛡️ AI-Powered Phishing Website Detection System

> **An intelligent cybersecurity tool that detects phishing websites using Machine Learning by analyzing domain data, SSL, WHOIS, and content features.**

---

## 🚀 Features

- 🔍 Real-time **URL phishing detection**
- 🧠 **Machine Learning model** trained on phishing & legit datasets
- 🔗 **Domain & URL pattern** analysis
- 🔐 **SSL certificate** verification
- 🌐 **WHOIS lookup** for domain metadata
- 🧾 **HTML content** parsing for phishing behavior
- ⚙️ **Redirect chain** analysis
- 🖥️ Simple **web interface** for live URL checking
- 📊 Central **logging & reporting system**
- **Multiple ML Models**: Implements and compares three powerful algorithms:
  - Random Forest
  - XGBoost
  - Support Vector Machine (SVM)
- **Feature Extraction**: Extracts 23 different features from URLs including:
  - URL structure analysis
  - Domain characteristics
  - SSL certificate information
  - WHOIS data
  - Website content analysis
- **Model Performance Visualization**: Generates detailed visualizations:
  - Confusion matrices for each model
  - Feature importance plots
  - Model comparison charts
- **Cross-validation**: Implements 5-fold cross-validation for robust model evaluation
- **Automatic Model Selection**: Automatically selects the best performing model based on F1-score
- **Live Dataset Updates**: Downloads fresh data from:
  - PhishTank for phishing URLs
  - Alexa Top Sites for legitimate URLs

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git (for cloning the repository)

### Step-by-Step Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/kunal-masurkar/AI-Powered-Phishing-Website-Detection-System.git
   cd AI-Powered-Phishing-Website-Detection-System
   ```

2. **Create and Activate Virtual Environment**
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate

   # On macOS/Linux
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download and Prepare Dataset**
   ```bash
   python download_dataset.py
   ```
   This will:
   - Download phishing URLs from PhishTank
   - Download legitimate URLs from Alexa Top Sites
   - Create a balanced dataset for training

5. **Train the Models**
   ```bash
   python train_model.py
   ```
   This will:
   - Extract features from the dataset
   - Train multiple ML models (Random Forest, XGBoost, SVM)
   - Generate performance visualizations
   - Save the best performing model

6. **Start the Web Application**
   ```bash
   python app.py
   ```

7. **Access the Web Interface**
   - Open your web browser
   - Go to http://localhost:5000
   - Enter a URL to analyze
   - Click "Analyze" to get the prediction

### Testing the System

1. **Test with Known URLs**
   - Try legitimate URLs like:
     - https://www.google.com
     - https://www.github.com
   - Try suspicious URLs from PhishTank (for testing)

2. **Check the Results**
   - The system will show:
     - Prediction (Legitimate/Phishing)
     - Confidence score
     - Detailed analysis of features
     - Visual indicators

### Troubleshooting

1. **If dataset download fails:**
   - Check your internet connection
   - Verify you have write permissions in the project directory
   - Try running `download_dataset.py` again

2. **If model training fails:**
   - Ensure all dependencies are installed correctly
   - Check if the dataset files exist in the `data/` directory
   - Verify you have sufficient disk space

3. **If web app doesn't start:**
   - Check if port 5000 is available
   - Verify the model files exist in the `models/` directory
   - Check the console for error messages

### Directory Structure After Setup

After running all the steps, you should have:
```
📦 AI-Powered-Phishing-Website-Detection-System/
├── data/
│   ├── phishing_urls.csv
│   ├── legitimate_urls.csv
│   └── balanced_dataset.csv
├── models/
│   ├── phishing_detector.joblib
│   ├── feature_names.joblib
│   ├── random_forest_confusion_matrix.png
│   ├── xgboost_confusion_matrix.png
│   ├── svm_confusion_matrix.png
│   ├── random_forest_feature_importance.png
│   ├── xgboost_feature_importance.png
│   └── model_comparison.png
└── ... (other files)
```

---

## 🏗️ Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/kunal-masurkar/AI-Powered-Phishing-Website-Detection-System.git
cd AI-Powered-Phishing-Website-Detection-System
```

### 2. Set Up Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install All Dependencies
```bash
pip install -r requirements.txt
```

---

## ⚙️ Usage

### 1. Train the ML Model (First Time Only)
```bash
python train_model.py
```

### 2. Launch the Web App
```bash
python app.py
```

### 3. Open Browser
Visit: [http://localhost:5000](http://localhost:5000)  
Paste any suspicious URL and click **"Analyze"** to get the prediction.

---

## 📁 Project Structure

```
📦 AI-Powered-Phishing-Website-Detection-System/
├── app.py                 # 🌐 Flask Web Application
├── train_model.py         # 🧠 ML Model Training Script
├── feature_extractor.py   # 🔍 Feature Extraction Logic
├── models/                # 🧾 Trained Model Files
├── static/                # 🎨 CSS / JS / Assets
├── templates/             # 📄 HTML Templates
├── requirements.txt       # 📦 Dependency List
├── data/                  # Data storage directory
│   ├── phishing_urls.csv     # Downloaded phishing URLs
│   ├── legitimate_urls.csv   # Downloaded legitimate URLs
│   └── balanced_dataset.csv  # Balanced training dataset
├── models/                # Model storage directory
│   ├── phishing_detector.joblib    # Best performing model
│   ├── feature_names.joblib        # Feature names for prediction
│   ├── *_confusion_matrix.png      # Confusion matrices
│   ├── *_feature_importance.png    # Feature importance plots
│   └── model_comparison.png        # Model comparison chart
├── static/                # Static files for web interface
│   ├── css/
│   │   └── style.css        # Custom styles
│   ├── js/
│   │   └── main.js          # Frontend JavaScript
│   └── favicon.ico          # Website favicon
├── templates/             # HTML templates
│   └── index.html          # Main web interface
├── download_dataset.py     # Dataset preparation script
└── README.md              # Project documentation
```

---

## 🔄 How It Works

1. **User enters a URL** into the web interface.
2. The system **extracts technical indicators**:
   - Domain patterns (length, special chars, subdomains)
   - SSL certificate data (validity, issuer, HTTPS usage)
   - WHOIS registration info (age, registrar)
   - HTML features (forms, JavaScript, iframes)
   - Redirect behavior
3. Extracted features are passed to a **trained Machine Learning model**.
4. Model predicts: ✅ Legitimate | ⚠️ Phishing
5. Results are shown to the user with insights & optional logging.

---

## 📚 Datasets & Models

- 🐟 **Phishing URLs:** [PhishTank](https://www.phishtank.com/)
- 🔒 **Legit URLs:** [Alexa Top Sites](https://www.alexa.com/topsites)
- 🤖 ML Algorithms: **Random Forest**, **XGBoost**, or **SVM**

---

## 🤝 Contributing

We welcome contributions from the community!  
Fork the repo, create a branch, make your changes, and submit a Pull Request.

---

## 📜 License

Licensed under the [Apache 2.0 License](LICENSE).

---

## 👥 Authors

| Name | GitHub | LinkedIn |
|------|--------|----------|
| **Kunal Masurkar** | [GitHub](https://github.com/kunal-masurkar) | [LinkedIn](https://linkedin.com/in/kunal-masurkar-8494a123a) |
| **Ayush Gorlawar** | [GitHub](https://github.com/AyushGorlawar) | [LinkedIn](https://www.linkedin.com/in/ayush-gorlawar) |
