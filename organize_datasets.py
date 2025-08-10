#!/usr/bin/env python3
"""
Dataset Organization Script
Helps organize and convert dataset files to the correct format for the threat detection system
"""

import os
import pandas as pd
import shutil
from pathlib import Path

def organize_datasets():
    """Organize and convert dataset files"""
    print("=" * 60)
    print("Dataset Organization Tool")
    print("=" * 60)
    
    # Create datasets directory if it doesn't exist
    datasets_dir = Path('datasets')
    datasets_dir.mkdir(exist_ok=True)
    
    print("📁 Organizing your dataset files...")
    
    # List of files to look for and organize
    files_to_organize = [
        # Spam datasets
        'spam',  # CSV file
        'SMSSpamCollection',  # SMS spam collection
        'Training Dataset.arff',  # ARFF training dataset
        
        # Phishing datasets  
        'Phishing Websites Features',  # Word document
        'verified_online',  # Large CSV file
        '.old.arff',  # ARFF file
        'readme'  # Documentation
    ]
    
    organized_files = []
    
    for filename in files_to_organize:
        # Check for variations of the filename
        possible_paths = [
            Path(filename),
            Path(f"{filename}.csv"),
            Path(f"{filename}.txt"),
            Path(f"{filename}.arff"),
            Path(f"{filename}.doc"),
            Path(f"{filename}.docx")
        ]
        
        for file_path in possible_paths:
            if file_path.exists():
                print(f"  ✅ Found: {file_path}")
                
                # Copy to datasets folder
                dest_path = datasets_dir / file_path.name
                shutil.copy2(file_path, dest_path)
                organized_files.append(dest_path)
                print(f"     📋 Copied to: {dest_path}")
                break
    
    print(f"\n📊 Summary:")
    print(f"  Total files organized: {len(organized_files)}")
    
    # Check for specific dataset types
    spam_files = [f for f in organized_files if 'spam' in f.name.lower() or 'sms' in f.name.lower()]
    phishing_files = [f for f in organized_files if 'phish' in f.name.lower() or 'verified' in f.name.lower()]
    
    print(f"  Spam-related files: {len(spam_files)}")
    print(f"  Phishing-related files: {len(phishing_files)}")
    
    # Provide conversion instructions
    print("\n🔄 Next Steps:")
    print("1. The files have been copied to the datasets/ folder")
    print("2. You may need to convert some files to CSV format")
    print("3. Run the training script: python train_models.py")
    
    return organized_files

def convert_arff_to_csv():
    """Convert ARFF files to CSV format"""
    print("\n🔄 Converting ARFF files to CSV...")
    
    datasets_dir = Path('datasets')
    
    # Look for ARFF files
    arff_files = list(datasets_dir.glob('*.arff'))
    
    for arff_file in arff_files:
        try:
            print(f"  Converting: {arff_file.name}")
            
            # Read ARFF file
            with open(arff_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Find data section
            data_start = None
            for i, line in enumerate(lines):
                if line.strip().lower().startswith('@data'):
                    data_start = i + 1
                    break
            
            if data_start is None:
                print(f"    ⚠️  Could not find @data section in {arff_file.name}")
                continue
            
            # Extract data
            data_lines = []
            for line in lines[data_start:]:
                line = line.strip()
                if line and not line.startswith('%'):
                    data_lines.append(line)
            
            # Convert to CSV
            csv_filename = arff_file.stem + '.csv'
            csv_path = datasets_dir / csv_filename
            
            with open(csv_path, 'w', encoding='utf-8') as f:
                for line in data_lines:
                    f.write(line + '\n')
            
            print(f"    ✅ Converted to: {csv_filename}")
            
        except Exception as e:
            print(f"    ❌ Error converting {arff_file.name}: {e}")

def main():
    """Main function"""
    try:
        # Organize files
        files = organize_datasets()
        
        # Convert ARFF files
        convert_arff_to_csv()
        
        print("\n" + "=" * 60)
        print("✅ Dataset organization completed!")
        print("=" * 60)
        print("\n📋 Your datasets are now ready for training.")
        print("🚀 Next step: python train_models.py")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main() 