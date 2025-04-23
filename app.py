from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
from datetime import datetime

app = Flask(__name__)

predictions_log = []  # Global list to hold all predictions

# Load your trained model
model = joblib.load("/home/kim/Desktop/projects/detection/attack_detection_model.pkl")

# Expected feature names
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

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    features = data.get("features")
    if features is None:
        return jsonify({"error": "No features provided"}), 400

    try:
        features_df = pd.DataFrame([features], columns=expected_columns)
    except Exception as e:
        return jsonify({"error": f"Error constructing DataFrame: {str(e)}"}), 400

    try:
        prediction = model.predict(features_df)
        raw_prediction = prediction[0]
    except Exception as e:
        return jsonify({"error": f"Prediction error: {str(e)}"}), 500

    # Override logic for OTH flag
    override_prediction = "anomaly" if features[3] == "OTH" else raw_prediction

    # Log the result
    predictions_log.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "features": features,
        "prediction": override_prediction
    })

    return jsonify({"prediction": override_prediction})



@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', predictions=predictions_log[-20:])


@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    predictions_log.clear()
    return jsonify({
        "message": "Logs cleared successfully",
        "success": True,
        "normal_count": 0,
        "attack_count": 0
    })


@app.route('/get_predictions')
def get_predictions():
    latest_predictions = predictions_log[-20:]
    normal_count = sum(1 for p in latest_predictions if p["prediction"] == "normal")
    attack_count = sum(1 for p in latest_predictions if p["prediction"] == "attack")
    return jsonify({
        "predictions": latest_predictions,
        "normal_count": normal_count,
        "attack_count": attack_count
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
