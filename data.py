import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Updated columns list (43 columns: 41 features, 1 attack label, 1 difficulty level)
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty"
]

# Load the training data from the TXT file
train_file = '/home/kim/Desktop/projects/detection/archive/nsl-kdd/KDDTrain+.txt'
data_train = pd.read_csv(train_file, names=columns)

# Load the testing data from the TXT file
test_file = '/home/kim/Desktop/projects/detection/archive/nsl-kdd/KDDTest+.txt'
data_test = pd.read_csv(test_file, names=columns)

# Clean column names (strip any extra spaces)
data_train.columns = data_train.columns.str.strip()
data_test.columns = data_test.columns.str.strip()

# ✅ INSERT THIS BLOCK HERE (after loading and cleaning):
# Group all attacks under one label
data_train['label'] = data_train['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
data_test['label'] = data_test['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

# Define categorical features that need encoding
categorical_features = ["protocol_type", "service", "flag"]


# Define numerical features: all columns except the categorical ones, the label, and the difficulty level
numerical_features = [col for col in data_train.columns if col not in categorical_features + ["label", "difficulty"]]

# Separate features and labels for training and testing. Drop the "difficulty" column as it's not needed.
X_train = data_train.drop(["label", "difficulty"], axis=1)
y_train = data_train["label"]

X_test = data_test.drop(["label", "difficulty"], axis=1)
y_test = data_test["label"]

# Create a preprocessing pipeline for numerical and categorical features
preprocessor = ColumnTransformer(
    transformers=[
        ("num", StandardScaler(), numerical_features),
        ("cat", OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ]
)

# Create a pipeline that first preprocesses the data and then trains a Random Forest classifier
clf = Pipeline(steps=[
    ("preprocessor", preprocessor),
    ("classifier", RandomForestClassifier(n_estimators=100, random_state=42))
])

# Train the model
clf.fit(X_train, y_train)

# Make predictions on the test set
y_pred = clf.predict(X_test)

# Evaluate the model
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the trained model for later use
joblib.dump(clf, 'attack_detection_model.pkl')
