# Import Libraries
import pandas as pd
import numpy as np
import os, json, hashlib
import torch
import xgboost as xgb

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.base import BaseEstimator, TransformerMixin
# from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import RFECV
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score, recall_score, classification_report

from sentence_transformers import SentenceTransformer

# Import Data
# This excel file is the result of get-iocs.py (Including IOCs as separate fields)
alerts = pd.read_excel('updated_dataframe.xlsx')

column_name = alerts.columns.tolist()

# Separating the dataset and the target value ('Status')
alerts['Status'] = alerts['Status'].str.strip().str.lower()

X = alerts.drop('Status', axis=1)
y = alerts['Status']

# Cleaning all NA columns
X = X.dropna(axis=1, how='all')

# Categories and their count in whole dataset
print(y.value_counts())

# Label Encoding the target values ()
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.25, random_state=43, stratify=y_encoded)


# FineTuned BERT Transformer class
from transformers import BertTokenizer, BertModel, BertForSequenceClassification

class FineTunedBERTVectorizer(BaseEstimator, TransformerMixin):
    def __init__(self, model_path="./dapt_model", max_length=128, device=None):
        self.model_path = model_path
        self.max_length = max_length
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # Validate model path
        if not os.path.isdir(self.model_path):
            raise ValueError(f"Model path does not exist: {self.model_path}")

        # Load tokenizer and model
        self.tokenizer = BertTokenizer.from_pretrained(self.model_path)
        self.model = BertModel.from_pretrained(self.model_path)
        self.model.to(self.device)
        self.model.eval()

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        # Combine multiple text columns into one string per row
        texts = X.apply(lambda row: ' | '.join(row.astype(str)), axis=1).tolist()

        all_embeddings = []
        batch_size = 16

        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i+batch_size]
            inputs = self.tokenizer(
                batch_texts,
                padding=True,
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt"
            ).to(self.device)

            with torch.no_grad():
                outputs = self.model(**inputs)
                cls_embeddings = outputs.last_hidden_state[:, 0, :]
                all_embeddings.append(cls_embeddings.cpu().numpy())

        return np.vstack(all_embeddings)


bert_modelname = "bert-base-uncased"
tokenizer = BertTokenizer.from_pretrained(bert_modelname)

text_cols = ['Alarm Details', 'Analysis', 'Recommendation']
texts = X_train[text_cols].apply(lambda row: ' | '.join(row.astype(str)), axis=1).tolist()
labels = y_train
encodings = tokenizer(texts, padding=True, truncation=True, return_tensors="pt")

bertmodel = BertForSequenceClassification.from_pretrained(bert_modelname)


from transformers import BertForMaskedLM, TextDataset, DataCollatorForLanguageModeling, Trainer, TrainingArguments

# Load base BERT
tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
model = BertForMaskedLM.from_pretrained("bert-base-uncased")

# Load your corpus
# contentfile.txt -> Content that contains alert text line by line. One alert per line format. Take care of internal \n characters
dataset = TextDataset(
    tokenizer=tokenizer,
    file_path="contentfile.txt",
    block_size=128
)

# Prepare data collator for MLM
data_collator = DataCollatorForLanguageModeling(
    tokenizer=tokenizer,
    mlm=True,
    mlm_probability=0.15
)

# Training configuration
training_args = TrainingArguments(
    output_dir="./dapt_model",
    overwrite_output_dir=True,
    num_train_epochs=3,
    per_device_train_batch_size=8,
    save_steps=10_000,
    save_total_limit=2,
    logging_dir="./logs"
)

# Trainer setup
trainer = Trainer(
    model=model,
    args=training_args,
    data_collator=data_collator,
    train_dataset=dataset
)

# Run DAPT to train BERT on cybersecurity data corpus
trainer.train()

# Save the model and tokenizer under dapt_model directory
model.save_pretrained("./dapt_model")
tokenizer.save_pretrained("./dapt_model")


# Text/Categorical based Encoding
class TextHashEncoder(BaseEstimator, TransformerMixin):
    def __init__(self, columns=None, n_digits=8):
        self.columns = columns
        self.n_digits = n_digits

    def fit(self, X, y=None):
        return self

    def _hash_func(self, val):
        if pd.isna(val):
            return np.nan
        return int(hashlib.sha256(str(val).encode()).hexdigest(), 16) % (10 ** self.n_digits)

    def transform(self, X):
        X_copy = X.copy()
        cols = self.columns or X_copy.columns

        for col in cols:
            X_copy[col] = X_copy[col].apply(self._hash_func)

        return X_copy

    def get_feature_names_out(self, input_features=None):
        # Return the column names that were transformed
        return np.array(self.columns if self.columns else input_features)


# Identify column types -> Uncomment numerical_cols if needed
# numerical_cols = X.select_dtypes(include=['number']).columns.tolist()
text_cols = X.columns[X.columns.isin(['Alarm Details', 'Analysis', 'Recommendation'])].tolist()
categorical_cols = X.columns[X.columns.isin(['Incident Area', 'Severity', 'Domains', 'Emails', 'Filenames', 'Hash', 'IP',])].tolist()

# Preprocessing for numerical data
# numerical_transformer = SimpleImputer(strategy='mean')

# Preprocessing for categorical data
categorical_transformer = Pipeline(steps=[
    ('text_hash', TextHashEncoder(columns=categorical_cols))
])

# Combine preprocessing steps
preprocessor = ColumnTransformer(transformers=[
    ('bert', FineTunedBERTVectorizer(model_path="./dapt_model"), text_cols),
    # ('num', numerical_transformer, numerical_cols),
    ('cat', categorical_transformer, categorical_cols)
])

# Initialize the XGBoost Classifier model.
model = xgb.XGBClassifier(eval_metric='logloss', random_state=68)

# Create a pipeline with the preprocessor steps and use XGBoost's Feature selection
pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('feature_selector', RFECV(estimator=model, step=1, cv=StratifiedKFold(3), scoring='accuracy')),
])

# Train the model
print("Starting pipeline training...")
pipeline.fit(X_train, y_train)
print("Model Trained")


# Calculate Accuracy
y_pred = pipeline.predict(X_test)
print("Test Accuracy:", accuracy_score(y_test, y_pred))

# Calculate Precision and Recall
precision = precision_score(y_test, y_pred, average='macro')
recall = recall_score(y_test, y_pred, average='macro')

print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")

# Display the Confusion matrix
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm)

fig, ax = plt.subplots(figsize=(8, 6))
disp.plot(ax=ax, cmap='Blues', values_format='d')
plt.title("Confusion Matrix: Alerts Predicted vs Actual")
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.tight_layout()
plt.show()

# Display Classification Bar Graph
correct = np.sum(y_pred == y_test)
incorrect = np.sum(y_pred != y_test)

# Bar plot
labels = ['Correct Predictions', 'Incorrect Predictions']
counts = [correct, incorrect]

plt.figure(figsize=(6, 5))
bars = plt.bar(labels, counts, color=['green', 'red'])
plt.title("Alert Prediction Accuracy")
plt.ylabel("Number of Alerts")
plt.xticks(rotation=0)

for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 1, yval, ha='center', va='bottom')

plt.tight_layout()
plt.show()