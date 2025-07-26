# **Cybersecurity Alert Classification using BERT & XGBoost**

## **Overview**

This project focuses on building a machine learning pipeline to classify cybersecurity alerts using a combination of BERT transformer-based embeddings and **XGBoost**. The model leverages **domain-adaptive pretraining (DAPT)** of BERT fine-tuned on cybersecurity alert data, combined with engineered categorical features and feature selection.

Cybersecurity datasets often contain a large number of features and may include missing values that shouldn't be discarded outright. XGBoost is well-equipped to handle such scenarios, as it can manage missing data effectively. During training, it learns the optimal direction (left or right) for instances with missing values at each decision split, enabling the model to utilize incomplete data without compromising performance.

### **Features / Data Structure**

**The input data contains the following features: (These fields are just for example. If you have more data, please train on that as well.)** 

- `Alert Details` → Text
- `Analysis` → Text
- `Incident Area` → Category
- `Recommendation` → Text
- `Severity` → Category

**Enriched fields from Alert details and Analysis:**

- `Domains`
- `Emails`
- `Filenames`
- `Hash`
- `IP`
- `URLs`

These text fields are derived from prior security alert data and investigations carried out by analysts or security tools like XDR, SOAR, and others. To ensure the BERT model understands the nuances of cybersecurity language and context, it's recommended to train it on historical cybersecurity datasets — whether labeled or unlabeled — to capture the patterns, terminology, and structure unique to this domain.

## **Steps / Pipeline**

### **Data Ingestion**

- Load raw alert data from an Excel file.

### **IOC Enrichment**

- Extract Indicators of Compromise (IOCs) from alert details and summary fields for further enrichment.

### **Data Cleaning**

- Sanitize the data by handling and removing null or missing values to ensure data quality.

### **Train-Test Split**

- Split the dataset into training and testing subsets for unbiased model evaluation.

### **BERT DAPT Model Fine-tuning**

- Use a BERT transformer model fine-tuned on a cybersecurity corpus (`contentfile.txt`) — Domain Adaptive PreTraining (DAPT).
- Fine-tuned model is saved in the `dapt_model` directory.

### **Categorical Feature Handling**

- Manually identify categorical features (can be automated as needed).
- Encode categories using `HashEncoder`.

### **Pipeline Creation**

- Develop a preprocessing pipeline that combines categorical encoding and other data transformations.

### **Model Training**

- Train an XGBoost classifier using the processed features.
- Apply Recursive Feature Elimination with Cross-Validation (RFECV) for feature selection.

### **Evaluation**

- Evaluate model performance using accuracy and other relevant metrics.

## **Usage**

### **Requirements**

- Python 3.7+
- pandas
- scikit-learn
- xgboost
- transformers (BERT)
- category_encoders

### **Future Improvements**

- Expand IOC enrichment with additional threat intelligence feeds.
- Implement hyperparameter tuning for XGBoost.
- Deploy the model as an API for real-time alert classification.
