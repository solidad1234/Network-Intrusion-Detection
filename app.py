from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

app = Flask(__name__)

# Load your trained model (same as before)
model = joblib.load("/home/kim/Desktop/projects/detection/attack_detection_model.pkl")

# Expected feature names (same 41 columns as before)
expected_columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

# A global list to store predictions in memory for the dashboard
predictions_log = []

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    features = data.get("features", None)
    if features is None:
        return jsonify({"error": "No features provided"}), 400
    
    # Convert the input features to a DataFrame with the expected column names
    try:
        features_df = pd.DataFrame([features], columns=expected_columns)
    except Exception as e:
        return jsonify({"error": f"Error constructing DataFrame: {str(e)}"}), 400
    
    # Make the prediction
    try:
        prediction = model.predict(features_df)
    except Exception as e:
        return jsonify({"error": f"Error during prediction: {str(e)}"}), 500
    
    # Log the prediction with a timestamp for the dashboard
    predictions_log.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "features": features,   # or a subset if this is too large
        "prediction": prediction[0]
    })
    
    return jsonify({"prediction": prediction.tolist()})

@app.route('/dashboard')
def dashboard():
    """
    Renders a simple HTML page that displays the latest predictions from predictions_log.
    """
    # We pass predictions_log to the template
    return render_template('dashboard.html', predictions=predictions_log)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
