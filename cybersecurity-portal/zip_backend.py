import os
import zipfile

backend_dir = r'c:\Users\Sahil\Dropbox\My PC (LAPTOP-MQVV34RN)\Desktop\secureeye-portal\cybersecurity-portal\backend'
zip_path = r'c:\Users\Sahil\Dropbox\My PC (LAPTOP-MQVV34RN)\Desktop\secureeye-portal\cybersecurity-portal\backend.zip'

with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(backend_dir):
        # Exclude directories
        dirs[:] = [d for d in dirs if d not in ('venv', '__pycache__', '.pytest_cache')]
        for file in files:
            if file.endswith('.pyc') or file.endswith('.zip'): continue
            file_path = os.path.join(root, file)
            arcname = os.path.relpath(file_path, backend_dir)
            zipf.write(file_path, arcname)
print('Zipped successfully!')
