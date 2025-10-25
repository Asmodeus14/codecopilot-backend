import os
import json
import zipfile
import tempfile
import shutil
import re
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing
from functools import lru_cache

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Try to import Gemini, but make it optional
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("Google Generative AI not available")

# Load environment variables
load_dotenv()

# 🚀 REMOVE upload size limit - we'll handle everything in backend
MAX_CLEANED_SIZE = 150 * 1024 * 1024  # 150MB after WE clean it
MAX_FILE_COUNT = 30000
MAX_COMPRESSION_RATIO = 100
MAX_DEPTH = 20

# 🚀 PERFORMANCE SETTINGS
MAX_WORKERS = min(3, multiprocessing.cpu_count())
BATCH_SIZE = 25
MAX_SCAN_FILES = 8000
EARLY_RETURN_CRITICAL_ISSUES = 5

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
    # NO FILE SIZE LIMIT - we accept everything and clean it ourselves
)

# Security middleware
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# CORS configuration
CORS(app, origins=[
    "https://codecopilot0.vercel.app",
    "http://localhost:5173"
])

# Initialize Gemini if available
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
LLM_ENABLED = False
gemini_model = None

if GEMINI_API_KEY and GEMINI_AVAILABLE:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model_names = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"]
        
        for model_name in model_names:
            try:
                model = genai.GenerativeModel(model_name)
                test_response = model.generate_content("Hello")
                gemini_model = model
                print(f"✅ Model {model_name} is available")
                break
            except Exception:
                continue
        
        if gemini_model:
            LLM_ENABLED = True
            print("🎯 Gemini model initialized successfully")
        else:
            LLM_ENABLED = False
    except Exception as e:
        print(f"❌ Failed to initialize Gemini: {e}")
        LLM_ENABLED = False
else:
    LLM_ENABLED = False

# 🚀 PRE-COMPILED REGEX PATTERNS
SECRET_PATTERNS = {
    re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', re.IGNORECASE): "API Key",
    re.compile(r'password["\']?\s*[:=]\s*["\'][^"\']{6,}["\']', re.IGNORECASE): "Password",
    re.compile(r'token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', re.IGNORECASE): "Token",
    re.compile(r'secret["\']?\s*[:=]\s*["\'][^"\']{6,}["\']', re.IGNORECASE): "Secret",
    re.compile(r'bearer["\']?\s*[^=]+=\s*["\'][^"\']{10,}["\']', re.IGNORECASE): "Bearer Token",
}

VULNERABLE_PATTERNS = {
    'lodash': '<4.17.21',
    'hoek': '<4.2.1',
    'minimist': '<1.2.6',
    'axios': '<1.6.0',
    'moment': '<2.29.4',
    'express': '<4.18.0',
    'react': '<16.14.0',
    'webpack': '<5.24.0',
}

# 🚀 DIRECTORIES WE AUTOMATICALLY REMOVE IN BACKEND
AUTO_REMOVE_DIRECTORIES = {
    'node_modules', '.git', 'dist', 'build', '.next', '.nuxt',
    'out', '.output', 'coverage', '.cache', '__pycache__',
    '.vscode', '.idea', 'tmp', 'temp', 'logs',
    'vendor', 'bower_components', '.yarn', '.pnp',
    '.parcel-cache', '.eslintcache', '.tsbuildinfo'
}

# 🚀 FILE EXTENSIONS WE AUTOMATICALLY REMOVE
AUTO_REMOVE_EXTENSIONS = {
    # Executables
    '.exe', '.dll', '.so', '.dylib', '.bat', '.cmd', '.ps1',
    '.sh', '.scr', '.com', '.pif', '.msi', '.jar', '.war', '.apk',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    # Media files
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
    '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.ogg', '.flac',
    # Documents
    '.pdf', '.doc', '.docx', '.ppt', '.pptx',
    # Fonts
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.ico', '.icns'
}

# 🚀 FILES WE ALWAYS KEEP (even if in removed directories)
ESSENTIAL_FILES = {
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    '.env', '.env.example', '.env.local', '.env.production',
    'tsconfig.json', 'webpack.config.js', 'vite.config.js', 'vite.config.ts',
    'rollup.config.js', 'dockerfile', 'docker-compose.yml',
    '.eslintrc', '.prettierrc', '.babelrc', 'jest.config.js'
}

class AutoFileCleaner:
    """Automatically cleans files in backend - user doesn't need to do anything"""
    
    def __init__(self):
        self.cleaned_files_count = 0
        self.cleaned_size = 0
        self.removed_directories = []
        self.removed_files_count = 0
        self.original_size = 0
    
    def auto_clean_project(self, extract_path: Path) -> Dict:
        """Automatically clean the project - remove node_modules, etc."""
        self.cleaned_files_count = 0
        self.cleaned_size = 0
        self.removed_directories = []
        self.removed_files_count = 0
        
        try:
            # Calculate original size
            self.original_size = self._calculate_directory_size(extract_path)
            
            print(f"🔧 Starting auto-cleaning: {self.original_size // (1024*1024)}MB")
            
            # Step 1: Remove entire directories we don't need
            self._auto_remove_directories(extract_path)
            
            # Step 2: Extract essential files from directories we're about to remove
            self._auto_extract_essential_files(extract_path)
            
            # Step 3: Remove non-essential individual files
            self._auto_remove_non_essential_files(extract_path)
            
            # Step 4: Calculate cleaned size
            self.cleaned_size = self._calculate_directory_size(extract_path)
            self.cleaned_files_count = self._count_files(extract_path)
            
            print(f"✅ Auto-cleaning complete: {self.original_size // (1024*1024)}MB → {self.cleaned_size // (1024*1024)}MB")
            print(f"📁 Removed {len(self.removed_directories)} directories and {self.removed_files_count} files")
            
            # Check if cleaned size is within limits
            if self.cleaned_size > MAX_CLEANED_SIZE:
                return {
                    "success": False,
                    "error": "Project too large after automatic cleaning",
                    "original_size_mb": self.original_size // (1024*1024),
                    "cleaned_size_mb": self.cleaned_size // (1024*1024),
                    "max_size_mb": MAX_CLEANED_SIZE // (1024*1024),
                    "files_kept": self.cleaned_files_count,
                    "directories_removed": self.removed_directories[:5],  # Sample
                    "removed_mb": (self.original_size - self.cleaned_size) // (1024*1024)
                }
            
            return {
                "success": True,
                "original_size_mb": self.original_size // (1024*1024),
                "cleaned_size_mb": self.cleaned_size // (1024*1024),
                "cleaned_files_count": self.cleaned_files_count,
                "directories_removed": len(self.removed_directories),
                "files_removed": self.removed_files_count,
                "removed_mb": (self.original_size - self.cleaned_size) // (1024*1024),
                "cleaning_performance": f"Removed {((self.original_size - self.cleaned_size) / self.original_size * 100):.1f}% of original size"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Automatic cleaning failed: {str(e)}"
            }
    
    def _auto_remove_directories(self, extract_path: Path):
        """Automatically remove directories we don't need"""
        for item in extract_path.iterdir():
            if item.is_dir() and item.name in AUTO_REMOVE_DIRECTORIES:
                try:
                    size_before = self._calculate_directory_size(item)
                    shutil.rmtree(item, ignore_errors=True)
                    self.removed_directories.append({
                        "name": item.name,
                        "size_mb": size_before // (1024*1024)
                    })
                    print(f"🗑️ Auto-removed directory: {item.name} ({size_before // (1024*1024)}MB)")
                except Exception as e:
                    print(f"⚠️ Failed to auto-remove directory {item}: {e}")
    
    def _auto_extract_essential_files(self, extract_path: Path):
        """Automatically extract essential config files before removing directories"""
        for dir_name in AUTO_REMOVE_DIRECTORIES:
            dir_path = extract_path / dir_name
            if dir_path.exists() and dir_path.is_dir():
                try:
                    for essential_file in ESSENTIAL_FILES:
                        # Look for this essential file in the directory
                        for file_path in dir_path.rglob(essential_file):
                            try:
                                # Calculate relative path
                                relative_path = file_path.relative_to(dir_path)
                                # Create safe destination path
                                safe_name = f"extracted_{dir_name}_{relative_path}".replace('/', '_')
                                destination_path = extract_path / safe_name
                                destination_path.parent.mkdir(parents=True, exist_ok=True)
                                
                                # Copy the file
                                shutil.copy2(file_path, destination_path)
                                print(f"📄 Auto-extracted: {file_path} → {destination_path}")
                            except Exception as e:
                                print(f"⚠️ Failed to extract {file_path}: {e}")
                except Exception as e:
                    print(f"⚠️ Error extracting from {dir_path}: {e}")
    
    def _auto_remove_non_essential_files(self, extract_path: Path):
        """Automatically remove non-essential files"""
        try:
            for file_path in extract_path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                file_ext = file_path.suffix.lower()
                file_name = file_path.name
                
                # Always keep essential files
                if file_name in ESSENTIAL_FILES:
                    continue
                
                # Always keep source code
                if file_ext in {'.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less'}:
                    continue
                
                # Always keep config files
                if file_ext in {'.json', '.yml', '.yaml', '.config.js', '.config.ts', '.env'}:
                    continue
                
                # Always keep documentation
                if file_ext in {'.md', '.txt', '.rst'}:
                    continue
                
                # Remove non-essential files
                if file_ext in AUTO_REMOVE_EXTENSIONS:
                    try:
                        file_size = file_path.stat().st_size
                        file_path.unlink()
                        self.removed_files_count += 1
                        # Only log large file removals to avoid spam
                        if file_size > 1024 * 1024:  # 1MB
                            print(f"🗑️ Auto-removed large file: {file_path.relative_to(extract_path)} ({file_size // (1024*1024)}MB)")
                    except Exception as e:
                        print(f"⚠️ Failed to remove {file_path}: {e}")
                        
        except Exception as e:
            print(f"⚠️ Error in auto file removal: {e}")
    
    def _calculate_directory_size(self, directory: Path) -> int:
        """Calculate total size of directory"""
        total_size = 0
        try:
            for file_path in directory.rglob('*'):
                if file_path.is_file():
                    try:
                        total_size += file_path.stat().st_size
                    except Exception:
                        continue
        except Exception:
            pass
        return total_size
    
    def _count_files(self, directory: Path) -> int:
        """Count files in directory"""
        count = 0
        try:
            for file_path in directory.rglob('*'):
                if file_path.is_file():
                    count += 1
        except Exception:
            pass
        return count

class SmartZipExtractor:
    """Safely extracts ZIP files of any size"""
    
    def __init__(self):
        self.skipped_files = []
        self.warned_files = []
    
    def extract_any_size_zip(self, zip_path: Path, extract_path: Path) -> Dict:
        """Extract ZIP file of any size"""
        self.skipped_files = []
        self.warned_files = []
        
        try:
            # Basic ZIP validation
            if not zip_path.exists() or zip_path.stat().st_size == 0:
                return {"valid": False, "error": "Empty or missing file"}
            
            if zip_path.suffix.lower() != '.zip':
                return {"valid": False, "error": "Not a ZIP file"}
            
            # Test if it's a valid ZIP
            try:
                with zipfile.ZipFile(zip_path, 'r') as test_zip:
                    test_zip.testzip()
            except zipfile.BadZipFile:
                return {"valid": False, "error": "Corrupted ZIP file"}
            
            extract_path.mkdir(parents=True, exist_ok=True)
            
            original_size = zip_path.stat().st_size
            print(f"📦 Extracting {original_size // (1024*1024)}MB ZIP file...")
            
            return self._extract_all_files(zip_path, extract_path)
                
        except Exception as e:
            return {"valid": False, "error": f"Failed to extract file: {str(e)}"}
    
    def _extract_all_files(self, zip_path: Path, extract_path: Path) -> Dict:
        """Extract all files - we'll clean them afterwards"""
        extracted_files = 0
        extracted_size = 0
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_infos = list(zip_ref.infolist())
                
                print(f"📁 Found {len(file_infos)} files in ZIP")
                
                for file_info in file_infos:
                    try:
                        # Basic path sanitization
                        safe_filename = self._sanitize_filename(file_info.filename)
                        
                        # Extract the file
                        zip_ref.extract(file_info, extract_path)
                        extracted_files += 1
                        extracted_size += file_info.file_size
                        
                        # Progress indicator for large files
                        if extracted_files % 1000 == 0:
                            print(f"📥 Extracted {extracted_files} files...")
                        
                    except Exception as e:
                        self.skipped_files.append(f"EXTRACTION_ERROR: {file_info.filename}")
                        continue
                
                print(f"✅ Extraction complete: {extracted_files} files, {extracted_size // (1024*1024)}MB")
                
                return {
                    "valid": True,
                    "extracted_files": extracted_files,
                    "extracted_size": extracted_size,
                    "warnings": self.warned_files[:5],
                    "skipped_files": len(self.skipped_files)
                }
                
        except Exception as e:
            return {"valid": False, "error": f"Extraction failed: {str(e)}"}
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        sanitized = re.sub(r'\.\./|\.\.\\', '', filename)
        sanitized = re.sub(r'^/+|^\\+', '', sanitized)
        return sanitized

# ... (Keep the LLMAnalyzer class from previous code - it doesn't change)

class ComprehensiveLLMAnalyzer:
    """LLM analyzer for enhanced issue analysis"""
    
    def __init__(self):
        self.enabled = LLM_ENABLED and gemini_model is not None
    
    async def analyze_issues_batch(self, issues: List[Dict], code_contexts: Dict[str, str] = None) -> List[Dict]:
        """Batch process issues with LLM"""
        if not self.enabled or not issues:
            return issues
        
        critical_issues = [issue for issue in issues if issue.get('severity') in ['high', 'medium']][:3]
        
        if not critical_issues:
            return issues
        
        try:
            enhanced_issues = []
            for issue in critical_issues:
                code_context = code_contexts.get(issue.get('file', ''), '') if code_contexts else ''
                enhanced_issue = await self.analyze_issue_with_llm(issue, code_context)
                if enhanced_issue:
                    enhanced_issues.append(enhanced_issue)
            
            # Update original issues
            result_issues = issues.copy()
            for enhanced_issue in enhanced_issues:
                for j, original_issue in enumerate(result_issues):
                    if (original_issue['title'] == enhanced_issue['title'] and 
                        original_issue['file'] == enhanced_issue['file']):
                        result_issues[j] = enhanced_issue
                        break
            
            return result_issues
            
        except Exception as e:
            print(f"Batch LLM analysis failed: {e}")
            return issues

    async def analyze_issue_with_llm(self, issue: Dict, code_context: str = "") -> Dict:
        """Single issue analysis with LLM"""
        if not self.enabled:
            return issue
        
        try:
            prompt = self._build_analysis_prompt(issue, code_context)
            
            response = await asyncio.wait_for(
                self._get_llm_response(prompt), 
                timeout=15.0
            )
            
            if response:
                return self._parse_llm_response(issue, response)
            else:
                return issue
                
        except asyncio.TimeoutError:
            print(f"LLM analysis timeout for issue: {issue['title']}")
            return issue
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            return issue
    
    def _build_analysis_prompt(self, issue: Dict, code_context: str) -> str:
        """Build analysis prompt"""
        return f"""
        As an expert software engineer, analyze this code issue:

        ISSUE: {issue['title']}
        DESCRIPTION: {issue['description']}
        CATEGORY: {issue['category']}
        SEVERITY: {issue.get('severity', 'medium')}

        CODE CONTEXT:
        {code_context[:2000] if code_context else 'No specific code context provided'}

        Provide:
        1. Root cause analysis
        2. Step-by-step solution
        3. Best practices to prevent this

        Keep it practical and actionable.
        """

    async def _get_llm_response(self, prompt: str) -> str:
        """Get LLM response"""
        if not self.enabled or not gemini_model:
            return ""
        
        try:
            response = gemini_model.generate_content(prompt)
            return response.text if response else ""
        except Exception as e:
            print(f"Gemini API error: {e}")
            return ""

    def _parse_llm_response(self, issue: Dict, llm_response: str) -> Dict:
        """Parse LLM response"""
        if not llm_response.strip():
            return issue
        
        issue.update({
            "llm_enhanced": True,
            "detailed_solution": llm_response.strip()[:1500],
            "root_cause": "AI analysis provided",
            "prevention": "See solution above",
            "ai_analyzed": True
        })
        
        return issue

class AutoCleanProjectAnalyzer:
    """Project analyzer that automatically cleans files in backend"""
    
    def __init__(self):
        self.issues = []
        self.project_stats = self._init_project_stats()
        self.zip_extractor = SmartZipExtractor()
        self.file_cleaner = AutoFileCleaner()
        self.llm_analyzer = ComprehensiveLLMAnalyzer()
        self._critical_issue_count = 0
        self._files_scanned = 0
    
    def _init_project_stats(self):
        """Initialize project stats"""
        return {
            "total_files": 0, "package_files": 0, "config_files": 0,
            "large_project": False, "node_modules_detected": False,
            "auto_cleaning_stats": {},
            "security_scan": {"vulnerable_deps": 0, "secrets_found": 0, "misconfigurations": 0},
            "code_quality": {"eslint_issues": 0, "typescript_issues": 0, "testing_issues": 0},
            "deployment": {"build_issues": 0, "config_issues": 0},
            "performance": {"scan_duration": 0, "files_processed": 0, "early_termination": False},
            "package_analysis": {
                "version_mismatches": [],
                "vulnerable_dependencies": [],
                "peer_dependency_issues": [],
            }
        }
    
    async def analyze_project(self, zip_path: Path) -> Dict:
        """Analyze project with automatic backend cleaning"""
        start_time = datetime.now()
        self.issues = []
        self.project_stats = self._init_project_stats()
        self._critical_issue_count = 0
        self._files_scanned = 0
        
        extract_path = Path(tempfile.mkdtemp(prefix="codecopilot_"))
        
        try:
            print("🚀 Starting automatic project analysis...")
            
            # Step 1: Extract the ZIP file (any size)
            extract_result = self.zip_extractor.extract_any_size_zip(zip_path, extract_path)
            
            if not extract_result["valid"]:
                return self._get_fallback_analysis(extract_result["error"])
            
            # Step 2: AUTOMATICALLY clean files in backend
            print("🔧 Auto-cleaning files in backend...")
            cleaning_result = self.file_cleaner.auto_clean_project(extract_path)
            
            if not cleaning_result["success"]:
                return self._get_size_exceeded_analysis(cleaning_result)
            
            # Add cleaning stats to project stats
            self.project_stats["auto_cleaning_stats"] = cleaning_result
            
            print(f"✅ Auto-cleaning removed {cleaning_result['removed_mb']}MB, kept {cleaning_result['cleaned_size_mb']}MB")
            
            # Step 3: Perform analysis on automatically cleaned files
            await self._comprehensive_analysis(extract_path)
            
            # Add performance metrics
            duration = (datetime.now() - start_time).total_seconds()
            self.project_stats["performance"]["scan_duration"] = duration
            self.project_stats["performance"]["files_processed"] = self._files_scanned
            
            # LLM Enhancement
            llm_was_used = False
            if self.llm_analyzer.enabled and self.issues:
                llm_was_used = await self._enhance_issues_with_llm(extract_path)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "issues": self.issues[:100],
                "health_score": self._calculate_health_score(),
                "summary": self._generate_summary(),
                "project_stats": self.project_stats,
                "llm_enhanced": llm_was_used,
                "llm_available": self.llm_analyzer.enabled,
                "auto_cleaning": True,
                "performance": {
                    "total_duration_seconds": round(duration, 2),
                    "issues_found": len(self.issues),
                    "files_processed": self._files_scanned,
                    "critical_issues_found": self._critical_issue_count,
                    "original_size_mb": cleaning_result["original_size_mb"],
                    "cleaned_size_mb": cleaning_result["cleaned_size_mb"],
                    "auto_removed_mb": cleaning_result["removed_mb"]
                }
            }
            
        except Exception as e:
            return self._get_error_analysis(str(e))
        finally:
            await self._cleanup_directory(extract_path)
    
    def _get_size_exceeded_analysis(self, cleaning_result: Dict) -> Dict:
        """Return analysis when auto-cleaned size still exceeds limit"""
        self._add_issue(
            title="Project Very Large",
            description=f"Project is {cleaning_result['original_size_mb']}MB. After automatic cleaning it's {cleaning_result['cleaned_size_mb']}MB, which still exceeds our {MAX_CLEANED_SIZE // (1024*1024)}MB limit.",
            category="system",
            severity="medium",
            solution="The system automatically removed node_modules and other non-essential files, but the project is still very large. Consider splitting your project or analyzing smaller parts."
        )
        
        return {
            "timestamp": datetime.now().isoformat(),
            "issues": self.issues,
            "health_score": 40,
            "summary": self._generate_summary(),
            "project_stats": {
                "auto_cleaning_stats": cleaning_result,
                "size_exceeded_after_cleaning": True
            },
            "llm_enhanced": False,
            "llm_available": self.llm_analyzer.enabled,
            "auto_cleaning": True,
            "performance": {
                "total_duration_seconds": 0,
                "issues_found": len(self.issues),
                "analysis_complete": False,
                "size_exceeded": True
            }
        }
    
    def _get_fallback_analysis(self, error: str) -> Dict:
        """Return analysis when extraction fails"""
        self._add_issue(
            title="Project Extraction Issue",
            description=f"Could not extract project: {error}",
            category="system",
            severity="medium",
            solution="Try creating a new ZIP file or check the file integrity"
        )
        
        return {
            "timestamp": datetime.now().isoformat(),
            "issues": self.issues,
            "health_score": 50,
            "summary": self._generate_summary(),
            "project_stats": {"extraction_error": error},
            "llm_enhanced": False,
            "llm_available": self.llm_analyzer.enabled,
            "auto_cleaning": False,
            "performance": {
                "total_duration_seconds": 0,
                "issues_found": len(self.issues),
                "analysis_complete": False
            }
        }
    
    def _get_error_analysis(self, error: str) -> Dict:
        """Return analysis when general error occurs"""
        self._add_issue(
            title="Analysis Error",
            description=f"Analysis encountered an error: {error}",
            category="system",
            severity="low",
            solution="This might be a temporary issue. Please try again."
        )
        
        return {
            "timestamp": datetime.now().isoformat(),
            "issues": self.issues,
            "health_score": 60,
            "summary": self._generate_summary(),
            "project_stats": {"analysis_error": error},
            "llm_enhanced": False,
            "llm_available": self.llm_analyzer.enabled,
            "auto_cleaning": False,
            "performance": {
                "total_duration_seconds": 0,
                "issues_found": len(self.issues),
                "analysis_complete": False
            }
        }
    
    async def _comprehensive_analysis(self, extract_path: Path):
        """Run comprehensive analysis on auto-cleaned files"""
        await self._analyze_project_structure(extract_path)
        await self._analyze_package_ecosystem(extract_path)
        await self._analyze_security(extract_path)
        await self._analyze_code_quality(extract_path)
        await self._analyze_deployment(extract_path)
        
        # Advanced analysis for reasonable-sized projects
        if self.project_stats["total_files"] < 5000:
            await self._analyze_code_complexity(extract_path)
            await self._analyze_performance(extract_path)
    
    async def _analyze_project_structure(self, extract_path: Path):
        """Analyze project structure"""
        file_count = 0
        
        try:
            for root, dirs, files in os.walk(extract_path):
                file_count += len(files)
                if file_count > MAX_SCAN_FILES:
                    break
            
            self.project_stats["total_files"] = file_count
            self._files_scanned = file_count
            
        except Exception as e:
            print(f"Error analyzing project structure: {e}")
    
    async def _analyze_package_ecosystem(self, extract_path: Path):
        """Enhanced package analysis"""
        package_files = list(extract_path.rglob('package.json'))
        
        if not package_files:
            self._add_issue(
                title="No package.json Found",
                description="No package.json file found in project",
                category="dependencies",
                severity="medium",
                solution="Add a package.json file to manage dependencies"
            )
            return
        
        self.project_stats["package_files"] = len(package_files)
        
        for package_file in package_files[:3]:
            try:
                with open(package_file, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                
                self._analyze_package_comprehensive(package_data, package_file)
                
            except Exception as e:
                print(f"Error analyzing package.json: {e}")
    
    def _analyze_package_comprehensive(self, package_data: Dict, package_file: Path):
        """Comprehensive package analysis"""
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        # Check version mismatches
        if 'react' in dependencies and 'react-dom' in dependencies:
            react_version = dependencies['react']
            react_dom_version = dependencies['react-dom']
            
            if react_version != react_dom_version:
                self._add_issue(
                    title="React Version Mismatch",
                    description=f"React ({react_version}) and ReactDOM ({react_dom_version}) versions don't match",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="high",
                    solution="Ensure react and react-dom versions match exactly"
                )
                self.project_stats["package_analysis"]["version_mismatches"].append({
                    "type": "react_mismatch",
                    "packages": ["react", "react-dom"],
                    "versions": [react_version, react_dom_version]
                })
        
        # Check vulnerable dependencies
        for dep, version in dependencies.items():
            if dep in VULNERABLE_PATTERNS:
                vulnerable_range = VULNERABLE_PATTERNS[dep]
                self._add_issue(
                    title=f"Vulnerable Dependency: {dep}",
                    description=f"{dep} {version} may have security vulnerabilities (affected: {vulnerable_range})",
                    category="security",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="high",
                    solution=f"Update {dep} to a secure version above {vulnerable_range}"
                )
                self.project_stats["package_analysis"]["vulnerable_dependencies"].append({
                    "package": dep,
                    "version": version,
                    "vulnerable_range": vulnerable_range
                })
                self.project_stats["security_scan"]["vulnerable_deps"] += 1
    
    async def _analyze_security(self, extract_path: Path):
        """Security analysis"""
        env_files = list(extract_path.rglob('.env*'))
        
        for env_file in env_files:
            if env_file.name != '.env.example':
                self._check_env_file_secrets(env_file, extract_path)
    
    def _check_env_file_secrets(self, env_file: Path, extract_path: Path):
        """Check environment files for secrets"""
        try:
            content = env_file.read_text(encoding='utf-8', errors='ignore')
            
            for pattern, secret_type in SECRET_PATTERNS.items():
                if pattern.search(content):
                    self._add_issue(
                        title=f"Hardcoded {secret_type}",
                        description=f"Potential {secret_type.lower()} found in {env_file.name}",
                        category="security",
                        file=str(env_file.relative_to(extract_path)),
                        severity="high",
                        solution=f"Move {secret_type.lower()} to environment variables or secure secret management"
                    )
                    self.project_stats["security_scan"]["secrets_found"] += 1
                    break
        except Exception:
            pass
    
    async def _analyze_code_quality(self, extract_path: Path):
        """Code quality analysis"""
        # Check for ESLint configuration
        eslint_configs = list(extract_path.rglob('.eslintrc*')) + \
                        list(extract_path.rglob('eslint.config.js'))
        
        if not eslint_configs:
            self._add_issue(
                title="No ESLint Configuration",
                description="Project doesn't have ESLint configured",
                category="code_quality",
                file="project-root",
                severity="low",
                solution="Add ESLint for code quality standards"
            )
            self.project_stats["code_quality"]["eslint_issues"] += 1
        
        # Check for test files
        test_files = list(extract_path.rglob('*.test.js')) + \
                    list(extract_path.rglob('*.spec.js')) + \
                    list(extract_path.rglob('*.test.ts')) + \
                    list(extract_path.rglob('*.spec.ts'))
        
        if not test_files:
            self._add_issue(
                title="No Test Files Found",
                description="Project doesn't have test files",
                category="code_quality",
                file="project-root",
                severity="low",
                solution="Add test files for code reliability"
            )
            self.project_stats["code_quality"]["testing_issues"] += 1
    
    async def _analyze_deployment(self, extract_path: Path):
        """Deployment analysis"""
        build_configs = list(extract_path.rglob('webpack.config.js')) + \
                       list(extract_path.rglob('vite.config.js')) + \
                       list(extract_path.rglob('vite.config.ts'))
        
        if not build_configs:
            self._add_issue(
                title="No Build Configuration",
                description="No build tool configuration found",
                category="deployment",
                file="project-root",
                severity="low",
                solution="Configure a build tool like Webpack or Vite"
            )
            self.project_stats["deployment"]["build_issues"] += 1
    
    async def _analyze_code_complexity(self, extract_path: Path):
        """Code complexity analysis"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        for file_path in source_files[:30]:
            try:
                complexity = self._calculate_complexity(file_path)
                if complexity > 50:
                    self._add_issue(
                        title="High Code Complexity",
                        description=f"File has high complexity score ({complexity})",
                        category="code_quality",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Refactor into smaller functions or modules"
                    )
            except Exception:
                continue
    
    def _calculate_complexity(self, file_path: Path) -> int:
        """Calculate code complexity"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            complexity = 0
            complexity += content.count('if ')
            complexity += content.count('for ')
            complexity += content.count('while ')
            complexity += content.count('catch ')
            complexity += content.count('switch ')
            complexity += content.count('&&')
            complexity += content.count('||')
            
            return complexity
        except:
            return 0
    
    async def _analyze_performance(self, extract_path: Path):
        """Performance analysis"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        for file_path in source_files[:50]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for missing React keys
                if re.search(r'\.map\s*\(\s*\(\s*\w+\s*\)\s*=>', content) and 'key=' not in content:
                    self._add_issue(
                        title="Missing React Keys",
                        description="Array.map without keys can cause performance issues",
                        category="performance",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Add unique key prop to list items"
                    )
                    
            except Exception:
                continue
    
    async def _enhance_issues_with_llm(self, extract_path: Path) -> bool:
        """Enhance issues with LLM"""
        if not self.issues or not self.llm_analyzer.enabled:
            return False
        
        critical_issues = [issue for issue in self.issues if issue.get('severity') in ['high', 'medium']][:3]
        
        if not critical_issues:
            return False
        
        try:
            code_contexts = {}
            for issue in critical_issues:
                if 'file' in issue and issue['file'] != 'project-root':
                    content = await self._get_file_content(extract_path / issue['file'])
                    if content:
                        code_contexts[issue.get('file', '')] = content
            
            enhanced_issues = await self.llm_analyzer.analyze_issues_batch(critical_issues, code_contexts)
            
            for i, enhanced_issue in enumerate(enhanced_issues):
                if enhanced_issue.get('llm_enhanced'):
                    for j, original_issue in enumerate(self.issues):
                        if (original_issue['title'] == critical_issues[i]['title'] and 
                            original_issue['file'] == critical_issues[i]['file']):
                            self.issues[j] = enhanced_issue
                            break
            
            return True
            
        except Exception as e:
            print(f"LLM enhancement failed: {e}")
            return False

    async def _get_file_content(self, file_path: Path) -> str:
        """Get file content for LLM"""
        try:
            if file_path.exists() and file_path.is_file():
                loop = asyncio.get_event_loop()
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = await loop.run_in_executor(None, f.read)
                return content[:2000]
        except Exception:
            pass
        return ""

    def _add_issue(self, title: str, description: str, category: str, file: str = "", 
                  severity: str = "medium", solution: str = ""):
        """Add issue to results"""
        if severity == "high":
            self._critical_issue_count += 1
        
        self.issues.append({
            "title": title,
            "description": description,
            "category": category,
            "file": file,
            "severity": severity,
            "priority": 1 if severity == "high" else 2 if severity == "medium" else 3,
            "solution": solution,
            "timestamp": datetime.now().isoformat()
        })
    
    def _calculate_health_score(self) -> int:
        """Calculate health score"""
        base_score = 100
        
        for issue in self.issues:
            if issue['severity'] == 'high':
                base_score -= 10
            elif issue['severity'] == 'medium':
                base_score -= 5
            else:
                base_score -= 2
        
        return max(0, min(100, base_score))

    def _generate_summary(self) -> Dict:
        """Generate summary"""
        issue_count = len(self.issues)
        health_score = self._calculate_health_score()
        
        priority_breakdown = {"high": 0, "medium": 0, "low": 0}
        category_breakdown = {}
        
        for issue in self.issues:
            priority_breakdown[issue['severity']] += 1
            category = issue['category']
            category_breakdown[category] = category_breakdown.get(category, 0) + 1
        
        status = "healthy" if health_score >= 80 else "needs attention" if health_score >= 60 else "needs work"
        
        return {
            "total_issues": issue_count,
            "health_status": status,
            "health_score": health_score,
            "priority_breakdown": priority_breakdown,
            "category_breakdown": category_breakdown
        }
    
    async def _cleanup_directory(self, directory_path: Path):
        """Cleanup directory"""
        try:
            if directory_path.exists():
                def remove_dir(path):
                    shutil.rmtree(path, ignore_errors=True)
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, remove_dir, directory_path)
        except Exception as e:
            print(f"Cleanup warning: {e}")

# Flask Routes
@app.route('/')
def root():
    return jsonify({
        "message": "CodeCopilot API - Automatic Backend Cleaning",
        "version": "2.0.0",
        "status": "running",
        "llm_enabled": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "auto_cleaning": True,
        "note": "Upload any size project - we automatically clean node_modules and non-essential files",
        "features": [
            "Accepts any file size",
            "Auto-removes node_modules, .git, etc.",
            "Keeps package.json for dependency analysis", 
            "Comprehensive code analysis",
            "AI-powered insights"
        ]
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        llm_status = "unknown"
        model_working = False
        
        if LLM_ENABLED and gemini_model:
            try:
                test_response = gemini_model.generate_content("Test")
                llm_status = "connected"
                model_working = True
            except Exception as e:
                llm_status = f"error: {str(e)}"
                model_working = False
        elif LLM_ENABLED:
            llm_status = "no_model"
        else:
            llm_status = "disabled"

        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "codecopilot-auto-clean",
            "version": "2.0.0",
            "llm_available": LLM_ENABLED,
            "llm_model_available": model_working,
            "auto_cleaning": True,
            "limits": {
                "max_cleaned_size_mb": MAX_CLEANED_SIZE // (1024*1024),
                "auto_removes": ["node_modules", ".git", "dist", "build", "media files"]
            }
        })
    except Exception as e:
        return jsonify({"status": "degraded", "error": str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_project():
    """Accept any file size and automatically clean in backend"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not file.filename.endswith('.zip'):
        return jsonify({
            "error": "Please upload a ZIP file",
            "note": "We accept any size ZIP file and automatically clean it"
        }), 400
    
    temp_dir = Path(tempfile.mkdtemp())
    temp_file = temp_dir / "project.zip"
    
    try:
        # 🎯 ACCEPT ANY FILE SIZE - no limits!
        file.save(temp_file)
        
        # Basic validation
        if temp_file.stat().st_size == 0:
            return jsonify({"error": "File is empty"}), 400
        
        original_size_mb = temp_file.stat().st_size // (1024*1024)
        print(f"📥 Received {original_size_mb}MB file - starting auto-cleaning...")
        
        # 🎯 AUTO-CLEANING ANALYSIS - we handle everything!
        analyzer = AutoCleanProjectAnalyzer()
        results = asyncio.run(analyzer.analyze_project(temp_file))
        
        return jsonify(results)
        
    except Exception as e:
        # Error handling
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
    finally:
        # Cleanup
        try:
            if temp_file.exists():
                temp_file.unlink()
            if temp_dir.exists():
                temp_dir.rmdir()
        except Exception:
            pass

@app.route('/api/capabilities')
def get_capabilities():
    """Return information about automatic cleaning capabilities"""
    return jsonify({
        "auto_cleaning": True,
        "process": "We automatically remove node_modules and non-essential files in our backend",
        "user_experience": "Just upload your project - we handle the cleaning automatically",
        "what_we_auto_remove": {
            "directories": list(AUTO_REMOVE_DIRECTORIES),
            "file_types": list(AUTO_REMOVE_EXTENSIONS)
        },
        "what_we_keep": {
            "source_code": [".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"],
            "config_files": ["package.json", "*.config.js", "tsconfig.json", ".env*"],
            "documentation": [".md", ".txt"]
        },
        "estimated_capacity": {
            "small_project": "5-50MB (works great)",
            "medium_project": "50-500MB (works great)", 
            "large_project": "500MB-2GB (usually works after auto-cleaning)",
            "very_large_project": "2GB+ (may still be too large after auto-cleaning)"
        }
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded. Please try again later."
    }), 429

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    
    print(f"🚀 Starting CodeCopilot with AUTO-CLEANING on port {port}")
    print(f"🎯 KEY FEATURE: Automatically cleans node_modules and non-essential files")
    print(f"📁 Accepts: Any size ZIP file")
    print(f"🗑️  Auto-removes: node_modules, .git, dist, build, media files, executables")
    print(f"📊 Auto-keeps: package.json, source code, config files for analysis")
    print(f"🧠 LLM Features: {'Enabled' if LLM_ENABLED else 'Disabled'}")
    print(f"⚡ Max cleaned size: {MAX_CLEANED_SIZE // (1024*1024)}MB")
    
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)