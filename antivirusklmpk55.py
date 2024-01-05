import sys
import hashlib
import os
import requests
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QTextEdit

class VirusTotalScanner:
    def __init__(self):
        self.api_key = 'bec084c578589364ec9e24b469135f55ba4f7cb65ce003941ed5c14684d38ff2'  # Ganti dengan API key VirusTotal Anda

    def scan_file(self, file_path):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.api_key}
        files = {'file': (file_path, open(file_path, 'rb'))}

        response = requests.post(url, files=files, params=params)
        result = response.json()

        return result

class AntivirusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.vt_scanner = VirusTotalScanner()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel('Masukkan alamat folder yang ingin Anda periksa:')
        self.label.setStyleSheet('font-weight: bold; font-size: 12pt;')
        self.folder_path_input = QLineEdit()
        layout.addWidget(self.label)
        layout.addWidget(self.folder_path_input)

        self.scan_button = QPushButton('Pindai Folder')
        self.scan_button.clicked.connect(self.scan_folder_clicked)
        self.scan_button.setStyleSheet('padding: 8px; background-color: #4CAF50; color: white; border: none; border-radius: 4px;')
        layout.addWidget(self.scan_button)

        self.report_label = QLabel('Hasil Pemindaian:')
        self.report_label.setStyleSheet('font-weight: bold; font-size: 12pt;')
        layout.addWidget(self.report_label)

        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setStyleSheet('border: 1px solid #ccc; border-radius: 4px;')
        layout.addWidget(self.report_text)

        self.setLayout(layout)
        self.setWindowTitle('Antivirus Program Kelompok 55')
        self.setStyleSheet('background-color: #f0f0f0;')
        self.show()

    def scan_folder_clicked(self):
        folder_path = self.folder_path_input.text()
        if not os.path.isdir(folder_path):
            QMessageBox.warning(self, 'Peringatan', 'Silakan masukkan alamat folder yang valid!')
            return

        try:
            scan_result = {}
            for root, dirs, files in os.walk(folder_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'rb') as file:
                            file_hash = hashlib.md5(file.read()).hexdigest()
                        file_scan_result = self.vt_scanner.scan_file(file_path)
                        scan_result[file_name] = {'md5_hash': file_hash, 'scan_result': file_scan_result}
                    except Exception as e:
                        print(f'Error: {e}')

            # Tampilkan hasil pemindaian
            message = ''
            for file_name, data in scan_result.items():
                message += f'File: {file_name}\n'
                message += f'Hash MD5 file: {data["md5_hash"]}\n'
                message += f'Hasil pemindaian VirusTotal:\n'
                for key, value in data['scan_result'].items():
                    message += f'{key}: {value}\n'
                message += '\n'

            self.report_text.setText(message)

            # Simpan hasil pemindaian ke dalam file catatan di folder yang sama dengan file program
            hasil_pemindaian_file = os.path.join(os.path.dirname(__file__), 'hasil_pemindaian.txt')
            with open(hasil_pemindaian_file, 'w') as note:
                note.write(message)
                QMessageBox.information(self, 'Info', 'Hasil pemindaian disimpan dalam file hasil_pemindaian.txt')

            # Membuat presentasi grafis dari hasil pemindaian
            self.presentasi_hasil_pemindaian(scan_result)

        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Terjadi kesalahan: {str(e)}')

    def presentasi_hasil_pemindaian(self, scan_result):
        detected = 0
        undetected = 0
        for key, value in scan_result.items():
            if key.startswith('detected_'):
                if value:
                    detected += 1
                else:
                    undetected += 1

        if detected != 0 or undetected != 0:
            labels = ['Deteksi Positif', 'Deteksi Negatif']
            sizes = [detected, undetected]
            colors = ['#ff9999', '#66b3ff']
            explode = (0.1, 0)

            try:
                plt.figure(figsize=(7, 7))
                plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                plt.axis('equal')
                plt.title('Hasil Pemindaian VirusTotal')
                plt.show()
            except Exception as e:
                print(f'Error plotting: {e}')
        else:
            print("Tidak ada data yang valid untuk plot grafik.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    antivirus_app = AntivirusApp()
    sys.exit(app.exec_())
