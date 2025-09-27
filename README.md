# PhishingEmailDetector
# Phishing Email Detector

A Python-based **Phishing Email Detection Tool** that combines **heuristics (rule-based analysis)** and **machine learning (scikit-learn)** to classify emails as safe, suspicious, or phishing.  
The project includes a **Tkinter GUI**, **dark mode toggle**, and **PDF report generation** for results.

* * *

## 📂 Project Structure

    CYBER-PHISH-DETECTOR/
    │── emails.csv              # Dataset used for training (email text + labels)
    │── keywords.json           # Common phishing keywords, risky extensions, shorteners
    │── main.py                 # Main application (GUI + detection logic)
    │── phish_model.pkl         # Trained ML model (Logistic Regression)
    │── vectorizer.pkl          # TF-IDF vectorizer used for ML
    │── requirement.txt         # Python dependencies
    │── train_model.py          # Script to train the ML model

* * *

## Features

*   **Email Content Analysis**
    
    *   Detects phishing keywords in subject/body
        
    *   Flags risky attachments (.exe, .vbs, .com)
        
*   **Suspicious Link Detection**
    
    *   Extracts URLs from emails
        
    *   Detects domain mismatches
        
    *   Flags shortened URLs (bit.ly, tinyurl, etc.)
        
    *   Identifies non-secure HTTP links
        
*   **Pattern & Heuristic Analysis**
    
    *   Poor grammar & spelling detection
        
    *   Checks for ALL CAPS, multiple !!! or ???
        
    *   Assigns a **risk score (0–100)**
        
*   **Machine Learning Integration**
    
    *   Trained using **scikit-learn Logistic Regression**
        
    *   Uses TF-IDF vectorizer for text features
        
    *   Produces phishing/safe classification + confidence %
        
*   **Graphical User Interface (GUI)**
    
    *   Paste email text or open .txt / .eml files
        
    *   **Dark mode toggle** for better UX
        
    *   **Clear** button to reset inputs
        
    *   **Save Report** button to export results as PDF
        
*   **Educational Insights**
    
    *   Explains why each flag was triggered
        
    *   Helps users understand phishing tactics
        

* * *

## Installation

1.  Clone this repository:
    
        git clone https://github.com/your-repo/phishing-email-detector.git
        cd phishing-email-detector
    
2.  Install dependencies:
    
        pip install -r requirement.txt
    
3.  Main dependencies:
    
    *   tkinter
        
    *   scikit-learn
        
    *   joblib
        
    *   pyspellchecker
        
    *   reportlab
        
    *   pandas, numpy
        

* * *

## Usage

1.  **Run the Detector**
    
        python main.py
    
2.  Paste email text in the left panel or open an email file (.txt / .eml).
    
3.  Click **Scan** → Results will appear in the right panel.
    
4.  Use **Save Report** to export as PDF.
    
5.  Toggle **Dark Mode** for a better UI experience.
    
6.  **Train the ML Model**If you want to retrain the ML model:
    
        python train_model.py
    
    This will generate fresh phish\_model.pkl and vectorizer.pkl files.
    

* * *

## Example Output

    Phishing Detector Report — 2025-09-27
    ============================================================
    From: scam@fakebank.com
    Subject: Urgent! Verify Your Account
    Heuristics Result: Likely Phishing (score 85)
    ML Result: Phishing (confidence 92.5%)
    
    Reasons:
    - Suspicious keywords found
    - Domain mismatch
    - Risky attachment mention
    - Shortened URL used
    
    Suggested Action:
    Likely phishing: do not click links or open attachments.

* * *

## Future Improvements

*   Real-time email client integration (Outlook/Gmail)
    
*   Deep learning models (BERT/Transformers)
    
*   Cloud-based phishing detection service
    
*   Multi-language phishing support
    

* * *

Built as part of Cybersecurity Project (Bachelor of IT)