#!/usr/bin/env python3
"""
Test file upload functionality for FixOps UI
Tests SBOM, SARIF, and CNAPP ingestion endpoints
"""

import os
import requests
from pathlib import Path

BACKEND_URL = os.getenv("FIXOPS_API_URL", "http://localhost:8000")
API_KEY = os.getenv("FIXOPS_API_KEY", "demo-token")
HEADERS = {"X-API-Key": API_KEY}

def test_file_upload():
    """Test file upload endpoints."""
    print("="*80)
    print("FILE UPLOAD TESTING")
    print("="*80)
    
    # Check for test artifacts
    artifacts_dir = Path("artifacts")
    artefacts_dir = Path("artefacts")  # Note: typo in original
    
    test_files = []
    
    # Find SBOM files
    for dir_path in [artifacts_dir, artefacts_dir]:
        if dir_path.exists():
            sbom_files = list(dir_path.glob("**/*.cdx.json")) + list(dir_path.glob("**/*sbom*.json"))
            if sbom_files:
                test_files.append(("SBOM", sbom_files[0], "/inputs/sbom"))
            
            sarif_files = list(dir_path.glob("**/*.sarif"))
            if sarif_files:
                test_files.append(("SARIF", sarif_files[0], "/inputs/sarif"))
            
            cnapp_files = list(dir_path.glob("**/cnapp.json"))
            if cnapp_files:
                test_files.append(("CNAPP", cnapp_files[0], "/inputs/cnapp"))
    
    if not test_files:
        print("❌ No test files found in artifacts/ or artefacts/")
        print("   Looking for: *.cdx.json, *.sarif, cnapp.json")
        return False
    
    print(f"\n📁 Found {len(test_files)} test file(s)\n")
    
    # Test each file
    results = []
    for file_type, file_path, endpoint in test_files:
        print(f"Testing {file_type} upload: {file_path.name}")
        print(f"  Endpoint: {endpoint}")
        print(f"  File size: {file_path.stat().st_size} bytes")
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f, 'application/json')}
                response = requests.post(
                    f"{BACKEND_URL}{endpoint}",
                    headers={"X-API-Key": API_KEY},
                    files=files,
                    timeout=30
                )
            
            if response.status_code in [200, 201, 202]:
                print(f"  ✅ Upload successful! Status: {response.status_code}")
                try:
                    data = response.json()
                    print(f"  Response: {data}")
                except:
                    pass
                results.append(True)
            else:
                print(f"  ❌ Upload failed! Status: {response.status_code}")
                print(f"  Response: {response.text[:200]}")
                results.append(False)
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results.append(False)
        
        print()
    
    # Summary
    print("="*80)
    print("UPLOAD TEST SUMMARY")
    print("="*80)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✅ All file uploads successful!")
    else:
        print(f"⚠️ {total - passed} upload(s) failed")
    
    print("\n💡 To test via UI:")
    print("  1. Open http://localhost:3000/ingest")
    print("  2. Drag and drop files from artifacts/ or artefacts/ directory")
    print("  3. Verify upload progress and success messages")
    print("  4. Check /intelligence page for ingested findings")
    
    return passed == total

def test_ui_file_drop():
    """Generate instructions for manual UI file drop testing."""
    print("\n" + "="*80)
    print("MANUAL UI FILE DROP TESTING")
    print("="*80)
    
    print("\n📋 Step-by-step guide:")
    print("\n1. Open the FixOps UI at http://localhost:3000/ingest")
    print("\n2. Test with these files from your workspace:")
    
    artifacts_dir = Path("artifacts")
    artefacts_dir = Path("artefacts")
    
    for dir_path in [artifacts_dir, artefacts_dir]:
        if dir_path.exists():
            print(f"\n   From {dir_path}/:")
            
            # List SBOM files
            sbom_files = list(dir_path.glob("**/*.cdx.json"))[:3]
            if sbom_files:
                print(f"   📦 SBOM files:")
                for f in sbom_files:
                    print(f"      • {f}")
            
            # List SARIF files
            sarif_files = list(dir_path.glob("**/*.sarif"))[:3]
            if sarif_files:
                print(f"   🔍 SARIF files:")
                for f in sarif_files:
                    print(f"      • {f}")
            
            # List CNAPP files
            cnapp_files = list(dir_path.glob("**/cnapp.json"))
            if cnapp_files:
                print(f"   ☁️  CNAPP files:")
                for f in cnapp_files:
                    print(f"      • {f}")
    
    print("\n3. For each file type:")
    print("   • Select the correct format in the dropdown")
    print("   • Drag and drop the file into the upload zone")
    print("   • OR click to browse and select the file")
    print("   • Watch for upload progress indicator")
    print("   • Verify success toast notification")
    
    print("\n4. Verification:")
    print("   • Navigate to /intelligence page")
    print("   • Check that new findings appear")
    print("   • Verify data is correctly parsed and displayed")
    print("   • Check for any errors in browser console (F12)")
    
    print("\n5. Test error handling:")
    print("   • Try uploading an invalid file")
    print("   • Try uploading without selecting format")
    print("   • Verify appropriate error messages display")

if __name__ == "__main__":
    test_file_upload()
    test_ui_file_drop()
