import pandas as pd
from scipy.io import arff
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle
import os

print(" MEMULAI PELATIHAN AI SAFEGUARD ")

DATASET_PATH = 'dataset/Training Dataset.arff' 

if not os.path.exists(DATASET_PATH):
    print(f" ERROR: File '{DATASET_PATH}' tidak ditemukan.")
    exit()

try:
    print("\n1. Membaca dan membersihkan dataset ARFF...")
    
    raw_data, meta = arff.loadarff(DATASET_PATH)
    df = pd.DataFrame(raw_data)
 
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].apply(lambda x: x.decode('utf-8') if isinstance(x, bytes) else x)
        
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df = df.dropna()
    
    print(f"Dataset berhasil dibersihkan! Jumlah data bersih: {df.shape} baris, {df.shape} kolom.")

    fitur_kolom = df.columns[:-1]
    target_kolom = df.columns[-1]

    X = df[fitur_kolom]
    y = df[target_kolom]

    print("\n2. Memisahkan data latih (80%) dan data uji (20%)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)

    model_c45 = DecisionTreeClassifier(criterion='entropy', max_depth=10, random_state=42)
    model_c45.fit(X_train, y_train)

    print("\n4. Menguji model dan menghitung metrik performa...")
    y_pred = model_c45.predict(X_test)
    
    akurasi = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print(" HASIL UJIAN AI (CONFUSION MATRIX & AKURASI):")
    print(f"Akurasi Keseluruhan : {akurasi * 100:.2f}%")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nLaporan Lengkap:")
    print(classification_report(y_test, y_pred))
    MODEL_FILENAME = 'safeguard_model.pkl'
    print(f"\n5. Menyimpan model ke dalam file '{MODEL_FILENAME}'...")
    
    model_data = {
        'model': model_c45,
        'features': list(fitur_kolom)
    }
    
    with open(MODEL_FILENAME, 'wb') as file:
        pickle.dump(model_data, file)
        
    print("PELATIHAN SELESAI! Otak AI (safeguard_model.pkl) siap digunakan.")

except Exception as e:
    print(f"\n TERJADI KESALAHAN SAAT PELATIHAN: {str(e)}")