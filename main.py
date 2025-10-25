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

# 🚀 BALANCED PERFORMANCE CONSTANTS FOR RENDER
MAX_FILE_SIZE = 150 * 1024 * 1024  # 150MB (balanced - was 100MB)
MAX_EXTRACTED_SIZE = 300 * 1024 * 1024  # 300MB (balanced - was 200MB)
MAX_FILE_COUNT = 20000  # Balanced - was 10000
MAX_COMPRESSION_RATIO = 30
MAX_DEPTH = 15  # Balanced - was 10

# 🚀 BALANCED PERFORMANCE SETTINGS
MAX_WORKERS = min(3, multiprocessing.cpu_count())  # Balanced - was 2
BATCH_SIZE = 30  # Balanced - was 20
MAX_SCAN_FILES = 5000  # Balanced - was 2000
EARLY_RETURN_CRITICAL_ISSUES = 4  # Balanced - was 3

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
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

# Initialize Gemini if available with better error handling
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
LLM_ENABLED = False
gemini_model = None

if GEMINI_API_KEY and GEMINI_AVAILABLE:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        
        # Try different model names
        model_names = [
            "gemini-2.0-flash-exp",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-pro",
            "models/gemini-pro"
        ]
        
        # Test which models are available
        for model_name in model_names:
            try:
                print(f"Testing model: {model_name}")
                model = genai.GenerativeModel(model_name)
                # Quick test to see if model works
                test_response = model.generate_content("Hello")
                gemini_model = model
                print(f"✅ Model {model_name} is available")
                break
            except Exception as model_error:
                print(f"❌ Model {model_name} not available: {model_error}")
                continue
        
        if gemini_model:
            LLM_ENABLED = True
            print("🎯 Gemini model initialized successfully")
        else:
            print("⚠️ No Gemini models available. LLM features disabled.")
            LLM_ENABLED = False
            
    except Exception as e:
        print(f"❌ Failed to initialize Gemini: {e}")
        gemini_model = None
        LLM_ENABLED = False
else:
    if not GEMINI_API_KEY:
        print("ℹ️  GEMINI_API_KEY not set. LLM features disabled.")
    else:
        print("ℹ️  Google Generative AI package not available. LLM features disabled.")
    LLM_ENABLED = False

# 🚀 PRE-COMPILED REGEX PATTERNS FOR PERFORMANCE
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
}

# 🚀 SKIP PATHS FOR EARLY TERMINATION
SKIP_PATHS = {
    'node_modules', '.git', 'dist', 'build', '.next', 
    '.nuxt', 'out', '.output', 'coverage', '.cache',
    '__pycache__', '.vscode', '.idea', 'tmp', 'temp', 'logs',
    'vendor', 'bower_components', '.yarn', '.pnp',
    '.parcel-cache', '.eslintcache', '.tsbuildinfo'
}

class SmartSecurityScanner:
    """Smart security scanner that balances performance and file size support"""
    
    # 🎯 SMART FILE SKIPPING - Skip binaries but allow larger source files
    SKIP_EXTENSIONS = {
        # Executables
        '.bat', '.cmd', '.ps1', '.sh', '.scr', '.com', '.pif', '.msi',
        '.jar', '.war', '.apk', '.exe', '.dll', '.so', '.dylib',
        # Archives (nested)
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        # Very large media files
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.mp3', '.wav', '.ogg', '.flac',
        # Large documents
        '.pdf', '.doc', '.docx', '.ppt', '.pptx',
    }
    
    # 🎯 ALLOW these larger files but process them smartly
    LARGE_FILE_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.ico', '.icns'
    }
    
    def __init__(self):
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
        self.total_extracted_size = 0
    
    def validate_and_extract_zip(self, zip_path: Path, extract_path: Path) -> Dict:
        """Smart ZIP extraction that handles larger files efficiently"""
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
        self.total_extracted_size = 0
        
        try:
            if not self._is_valid_zip(zip_path):
                return {"valid": False, "error": "Invalid ZIP file"}
            
            # Smart bomb detection with progress tracking
            bomb_check = self._smart_detect_zip_bomb(zip_path)
            if not bomb_check["safe"]:
                return self._get_zip_bomb_error_message(bomb_check)
            
            extract_path.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                return self._smart_extract_files(zip_ref, extract_path)
                
        except zipfile.BadZipFile:
            return {"valid": False, "error": "Corrupted ZIP file"}
        except Exception as e:
            return {"valid": False, "error": f"Processing failed: {str(e)}"}

    def _smart_detect_zip_bomb(self, zip_path: Path) -> Dict:
        """Smart detection that handles larger files"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                total_files = 0
                total_uncompressed_size = 0
                max_compression_ratio = 0
                max_depth = 0
                
                for file_info in zip_ref.infolist():
                    # Skip security checks for allowed large files early
                    if self._is_large_media_file(file_info.filename):
                        continue
                    
                    # Security checks for other files
                    if '..' in file_info.filename or file_info.filename.startswith('/'):
                        return {"safe": False, "reason": "Path traversal attempt detected"}
                    
                    depth = file_info.filename.count('/') + file_info.filename.count('\\')
                    max_depth = max(max_depth, depth)
                    
                    if depth > MAX_DEPTH:
                        return {"safe": False, "reason": f"Excessive directory depth ({depth} levels)"}
                    
                    if file_info.compress_size > 0:
                        ratio = file_info.file_size / file_info.compress_size
                        max_compression_ratio = max(max_compression_ratio, ratio)
                        
                        if ratio > MAX_COMPRESSION_RATIO and not self._is_large_media_file(file_info.filename):
                            return {"safe": False, "reason": f"Suspicious compression ratio ({ratio:.1f}:1) in {file_info.filename}"}
                    
                    total_files += 1
                    total_uncompressed_size += file_info.file_size
                    
                    # Slightly more generous limits
                    if total_files > MAX_FILE_COUNT:
                        return {"safe": False, "reason": f"Too many files ({total_files} > {MAX_FILE_COUNT})"}
                    
                    if total_uncompressed_size > MAX_EXTRACTED_SIZE:
                        return {"safe": False, "reason": f"Total uncompressed size too large ({total_uncompressed_size // (1024*1024)}MB)"}
                
                return {"safe": True, "reason": "No threats detected"}
                
        except Exception as e:
            return {"safe": False, "reason": f"Security scan failed: {str(e)}"}

    def _smart_extract_files(self, zip_ref, extract_path: Path) -> Dict:
        """Smart extraction that handles larger files efficiently"""
        extracted_files = 0
        large_files_skipped = 0
        
        # First pass: count and plan
        file_infos = []
        for file_info in zip_ref.infolist():
            if self._should_skip_file_completely(file_info.filename):
                self.skipped_files.append(file_info.filename)
                continue
            
            if self._is_large_media_file(file_info.filename):
                large_files_skipped += 1
                self.skipped_files.append(file_info.filename)
                continue
            
            file_infos.append(file_info)
            extracted_files += 1
            
            if extracted_files > MAX_FILE_COUNT:
                return {"valid": False, "error": f"Too many files. Limit is {MAX_FILE_COUNT} files."}
        
        # Second pass: extract efficiently
        for file_info in file_infos:
            try:
                zip_ref.extract(file_info, extract_path)
                self.total_extracted_size += file_info.file_size
                
                if self.total_extracted_size > MAX_EXTRACTED_SIZE:
                    return {"valid": False, "error": f"Project too large. Maximum extracted size is {MAX_EXTRACTED_SIZE // (1024*1024)}MB."}
                    
            except Exception as e:
                print(f"Warning: Failed to extract {file_info.filename}: {e}")
        
        return {
            "valid": True,
            "skipped_files": self.skipped_files[:100],
            "total_skipped": len(self.skipped_files),
            "extracted_files": extracted_files,
            "extracted_size": self.total_extracted_size,
            "large_files_skipped": large_files_skipped,
            "threats_detected": self.detected_threats
        }

    def _is_large_media_file(self, filename: str) -> bool:
        """Check if file is a large media file that can be skipped"""
        file_ext = Path(filename).suffix.lower()
        return file_ext in self.LARGE_FILE_EXTENSIONS

    def _should_skip_file_completely(self, filename: str) -> bool:
        """Check if file should be completely skipped"""
        file_path = Path(filename)
        file_ext = file_path.suffix.lower()
        filename_lower = filename.lower()
        
        # Skip dangerous/executable files
        if file_ext in self.SKIP_EXTENSIONS:
            return True
        
        # Skip unwanted directories
        if any(skip_dir in filename_lower for skip_dir in SKIP_PATHS):
            return True
        
        return False

    def _get_zip_bomb_error_message(self, bomb_check: Dict) -> Dict:
        """User-friendly error messages"""
        reason = bomb_check["reason"]
        
        if "compression ratio" in reason.lower():
            return {
                "valid": False,
                "error": "Suspicious compression detected",
                "details": "This file compresses too efficiently, which could indicate a security risk.",
                "user_tip": "Try zipping only your source code, not generated files.",
                "rejection_reason": "HIGH_COMPRESSION_RATIO"
            }
        elif "too many files" in reason.lower():
            return {
                "valid": False,
                "error": "Project contains too many files",
                "details": f"This project has more than {MAX_FILE_COUNT} files.",
                "user_tip": "Try removing the node_modules folder before zipping.",
                "rejection_reason": "TOO_MANY_FILES"
            }
        elif "path traversal" in reason.lower():
            return {
                "valid": False,
                "error": "Invalid file paths detected",
                "details": "Some files use paths that could access files outside your project folder.",
                "user_tip": "Re-zip your project from inside the project folder.",
                "rejection_reason": "PATH_TRAVERSAL_ATTEMPT"
            }
        elif "directory depth" in reason.lower():
            return {
                "valid": False,
                "error": "Excessive directory depth",
                "details": "The project folder structure is too deeply nested.",
                "user_tip": "Simplify your project structure and re-zip the project.",
                "rejection_reason": "EXCESSIVE_DEPTH"
            }
        else:
            return {
                "valid": False,
                "error": "Security check failed",
                "details": "This file exhibits characteristics that could pose a security risk.",
                "user_tip": "Try creating a fresh ZIP file of your project source code.",
                "rejection_reason": "GENERAL_SECURITY_FAILURE"
            }

    def _is_valid_zip(self, file_path: Path) -> bool:
        """ZIP validation"""
        return (file_path.suffix.lower() == '.zip' and 
                file_path.exists() and 
                file_path.stat().st_size > 0)

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

class BalancedLLMAnalyzer:
    """Balanced LLM analyzer for better performance"""
    
    def __init__(self):
        self.enabled = LLM_ENABLED and gemini_model is not None
    
    async def analyze_issues_batch(self, issues: List[Dict], code_contexts: Dict[str, str] = None) -> List[Dict]:
        """Batch process issues with LLM"""
        if not self.enabled or not issues:
            return issues
        
        # Analyze critical and high-impact medium issues
        critical_issues = [issue for issue in issues if issue.get('severity') in ['high', 'medium']][:4]
        
        if not critical_issues:
            return issues
        
        try:
            enhanced_issues = []
            for issue in critical_issues:
                enhanced_issue = await self.analyze_issue_with_llm(issue, code_contexts.get(issue.get('file', ''), ''))
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
        """Single issue analysis with balanced timeout"""
        if not self.enabled:
            return issue
        
        try:
            prompt = self._build_analysis_prompt(issue, code_context)
            
            response = await asyncio.wait_for(
                self._get_llm_response(prompt), 
                timeout=12.0  # Balanced timeout
            )
            
            if response:
                return self._parse_llm_response(issue, response)
            else:
                issue["llm_fallback"] = "AI analysis temporarily unavailable"
                return issue
                
        except asyncio.TimeoutError:
            print(f"LLM analysis timeout for issue: {issue['title']}")
            issue["llm_fallback"] = "AI analysis timeout"
            return issue
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            issue["llm_fallback"] = "AI analysis failed - showing basic analysis"
            return issue
    
    def _build_analysis_prompt(self, issue: Dict, code_context: str) -> str:
        """Balanced prompt building"""
        return f"""
        As an expert web developer, analyze this code issue:

        ISSUE: {issue['title']}
        DESCRIPTION: {issue['description']}
        CATEGORY: {issue['category']}
        SEVERITY: {issue.get('severity', 'medium')}

        CODE:
        {code_context[:2000] if code_context else 'No code context'}

        Provide:
        1. Root cause (brief)
        2. Step-by-step solution
        3. Prevention tips

        Keep it practical and concise.
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
            issue["llm_enhanced"] = False
            return issue
        
        issue.update({
            "llm_enhanced": True,
            "detailed_solution": llm_response.strip()[:1500],
            "root_cause": "AI analysis provided",
            "prevention": "See solution above",
            "ai_analyzed": True
        })
        
        return issue

class BalancedProjectAnalyzer:
    """Balanced project analyzer that supports larger files"""
    
    def __init__(self):
        self.issues = []
        self.project_stats = self._init_project_stats()
        self.security_scanner = SmartSecurityScanner()
        self.llm_analyzer = BalancedLLMAnalyzer()
        self._critical_issue_count = 0
        self._files_scanned = 0
    
    def _init_project_stats(self):
        """Initialize project stats"""
        return {
            "total_files": 0, "package_files": 0, "config_files": 0,
            "large_project": False, "node_modules_detected": False,
            "skipped_files": 0, "large_files_skipped": 0,
            "security_scan": {"vulnerable_deps": 0, "secrets_found": 0, "misconfigurations": 0},
            "code_quality": {"eslint_issues": 0, "typescript_issues": 0, "testing_issues": 0},
            "deployment": {"build_issues": 0, "config_issues": 0},
            "performance": {"scan_duration": 0, "files_processed": 0, "early_termination": False},
        }
    
    async def analyze_project(self, zip_path: Path) -> Dict:
        """Balanced project analysis that handles larger files"""
        start_time = datetime.now()
        self.issues = []
        self.project_stats = self._init_project_stats()
        self._critical_issue_count = 0
        self._files_scanned = 0
        
        extract_path = Path(tempfile.mkdtemp(prefix="codecopilot_"))
        
        try:
            # Extract with smart security scanning
            extract_result = self.security_scanner.validate_and_extract_zip(zip_path, extract_path)
            
            if not extract_result["valid"]:
                if "rejection_reason" in extract_result:
                    raise ValueError(json.dumps(extract_result))
                else:
                    raise ValueError(extract_result["error"])
            
            # Update stats
            self.project_stats["skipped_files"] = extract_result["total_skipped"]
            self.project_stats["large_files_skipped"] = extract_result.get("large_files_skipped", 0)
            
            # 🚀 BALANCED ANALYSIS
            await self._balanced_analysis(extract_path)
            
            # Project size classification
            if self.project_stats["total_files"] > 1000:
                self.project_stats["large_project"] = True
            
            # Early termination for very critical issues only
            if self._critical_issue_count >= EARLY_RETURN_CRITICAL_ISSUES:
                self.project_stats["performance"]["early_termination"] = True
                self._add_issue(
                    title="Analysis optimized for performance",
                    description=f"Found {self._critical_issue_count} critical issues. Analysis optimized.",
                    category="performance",
                    file="project-root",
                    severity="low"
                )
            
            # LLM enhancement
            llm_was_used = False
            if self.llm_analyzer.enabled and self.issues:
                llm_was_used = await self._enhance_issues_with_llm(extract_path)
            
            # Performance metrics
            duration = (datetime.now() - start_time).total_seconds()
            self.project_stats["performance"]["scan_duration"] = duration
            self.project_stats["performance"]["files_processed"] = self._files_scanned
            
            return {
                "timestamp": datetime.now().isoformat(),
                "issues": self.issues[:100],  # Return more issues
                "health_score": self._calculate_health_score(),
                "summary": self._generate_summary(),
                "project_stats": self.project_stats,
                "llm_enhanced": llm_was_used,
                "llm_available": self.llm_analyzer.enabled,
                "performance": {
                    "total_duration_seconds": round(duration, 2),
                    "issues_found": len(self.issues),
                    "early_termination": self.project_stats["performance"]["early_termination"],
                    "files_processed": self._files_scanned,
                    "critical_issues_found": self._critical_issue_count,
                    "max_file_size_supported": f"{MAX_FILE_SIZE // (1024*1024)}MB"
                }
            }
        finally:
            await self._cleanup_directory(extract_path)
    
    async def _balanced_analysis(self, extract_path: Path):
        """Balanced analysis with smart resource usage"""
        # Core analysis (always run)
        await self._fast_count_files(extract_path)
        await self._analyze_package_files_balanced(extract_path)
        await self._check_security_issues_balanced(extract_path)
        
        # Extended analysis (for reasonable-sized projects)
        if self.project_stats["total_files"] < 2000:
            await self._check_code_quality_balanced(extract_path)
            await self._check_deployment_balanced(extract_path)
            
            # Advanced features (for smaller projects)
            if self.project_stats["total_files"] < 800:
                await self._check_dependency_vulnerabilities(extract_path)
                await self._analyze_code_complexity_balanced(extract_path)
    
    async def _fast_count_files(self, extract_path: Path):
        """Fast file counting"""
        file_count = 0
        try:
            for root, dirs, files in os.walk(extract_path):
                dirs[:] = [d for d in dirs if d not in SKIP_PATHS]
                if 'node_modules' in root:
                    self.project_stats["node_modules_detected"] = True
                    dirs.clear()
                    continue
                file_count += len(files)
                if file_count > MAX_SCAN_FILES:
                    break
            
            self.project_stats["total_files"] = file_count
            self._files_scanned = min(file_count, MAX_SCAN_FILES)
        except Exception as e:
            print(f"Error counting files: {e}")
            self.project_stats["total_files"] = 0
    
    async def _analyze_package_files_balanced(self, extract_path: Path):
        """Balanced package analysis"""
        package_files = list(extract_path.rglob('package.json'))
        package_files = [pf for pf in package_files if 'node_modules' not in str(pf)]
        
        if not package_files:
            return
        
        self.project_stats["package_files"] = len(package_files)
        
        # Analyze up to 5 package files
        for package_file in package_files[:5]:
            self._analyze_single_package(package_file)
    
    def _analyze_single_package(self, package_file: Path):
        """Analyze single package.json"""
        try:
            with open(package_file, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
            
            # Essential checks only
            self._check_dependencies(package_data, package_file)
            self._check_scripts(package_data, package_file)
            self._check_vulnerable_dependencies(package_data, package_file)
            
        except Exception as e:
            print(f"Error analyzing package.json: {e}")
    
    def _check_dependencies(self, package_data: Dict, package_file: Path):
        """Check dependency issues"""
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        # React version check
        if 'react' in dependencies and 'react-dom' in dependencies:
            react_version = dependencies['react']
            react_dom_version = dependencies['react-dom']
            
            if react_version != react_dom_version:
                self._add_issue(
                    title="React Version Mismatch",
                    description=f"React ({react_version}) and ReactDOM ({react_dom_version}) versions don't match",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="medium",
                    solution="Ensure react and react-dom versions match"
                )
    
    def _check_scripts(self, package_data: Dict, package_file: Path):
        """Check package scripts"""
        scripts = package_data.get('scripts', {})
        
        if 'start' not in scripts and 'dev' not in scripts:
            self._add_issue(
                title="Missing Start Script",
                description="No start or dev script found",
                category="configuration",
                file=str(package_file.relative_to(package_file.parent.parent)),
                severity="low",
                solution="Add a 'start' or 'dev' script"
            )
    
    def _check_vulnerable_dependencies(self, package_data: Dict, package_file: Path):
        """Check for vulnerable dependencies"""
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        for dep, version in dependencies.items():
            if dep in VULNERABLE_PATTERNS:
                vulnerable_version = VULNERABLE_PATTERNS[dep]
                self._add_issue(
                    title=f"Vulnerable Dependency: {dep}",
                    description=f"{dep} {version} has known vulnerabilities",
                    category="security",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="high",
                    solution=f"Update {dep} to version above {vulnerable_version}"
                )
                self.project_stats["security_scan"]["vulnerable_deps"] += 1
    
    async def _check_security_issues_balanced(self, extract_path: Path):
        """Balanced security scanning"""
        # Check critical config files
        critical_configs = [
            extract_path / '.env',
            extract_path / '.env.local',
            extract_path / '.env.production',
        ]
        
        for config_file in critical_configs:
            if config_file.exists():
                self._scan_file_for_secrets(config_file)
    
    def _scan_file_for_secrets(self, file_path: Path):
        """Scan file for secrets"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            for pattern, secret_type in SECRET_PATTERNS.items():
                if pattern.search(content):
                    self._add_issue(
                        title=f"Hardcoded {secret_type}",
                        description=f"Potential {secret_type.lower()} found",
                        category="security",
                        file=str(file_path.relative_to(file_path.parent.parent.parent)),
                        severity="high",
                        solution=f"Move {secret_type.lower()} to environment variables"
                    )
                    self.project_stats["security_scan"]["secrets_found"] += 1
                    break
        except Exception:
            pass
    
    async def _check_code_quality_balanced(self, extract_path: Path):
        """Balanced code quality checks"""
        await self._check_eslint_config(extract_path)
        await self._check_typescript_config(extract_path)
        await self._check_testing_setup(extract_path)
    
    async def _check_eslint_config(self, extract_path: Path):
        """Check ESLint config"""
        eslint_configs = list(extract_path.rglob('.eslintrc*')) + \
                        list(extract_path.rglob('eslint.config.js'))
        
        if not eslint_configs:
            self._add_issue(
                title="No ESLint Configuration",
                description="Project doesn't have ESLint configured",
                category="code_quality",
                file="project-root",
                severity="low",
                solution="Add ESLint for code quality"
            )
            self.project_stats["code_quality"]["eslint_issues"] += 1
    
    async def _check_typescript_config(self, extract_path: Path):
        """Check TypeScript config"""
        tsconfig_files = list(extract_path.rglob('tsconfig.json'))
        
        if tsconfig_files:
            for tsconfig in tsconfig_files[:1]:
                try:
                    with open(tsconfig, 'r') as f:
                        tsconfig_data = json.load(f)
                    
                    compiler_options = tsconfig_data.get('compilerOptions', {})
                    if not compiler_options.get('strict'):
                        self._add_issue(
                            title="TypeScript Strict Mode Disabled",
                            description="Strict mode is not enabled",
                            category="code_quality",
                            file=str(tsconfig.relative_to(extract_path)),
                            severity="medium",
                            solution="Enable strict mode in tsconfig.json"
                        )
                        self.project_stats["code_quality"]["typescript_issues"] += 1
                except Exception:
                    pass
    
    async def _check_testing_setup(self, extract_path: Path):
        """Check testing setup"""
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
                solution="Add test files for reliability"
            )
            self.project_stats["code_quality"]["testing_issues"] += 1
    
    async def _check_deployment_balanced(self, extract_path: Path):
        """Balanced deployment checks"""
        await self._check_build_configs(extract_path)
        await self._check_environment_configs(extract_path)
    
    async def _check_build_configs(self, extract_path: Path):
        """Check build configurations"""
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
    
    async def _check_environment_configs(self, extract_path: Path):
        """Check environment configs"""
        env_example = extract_path / '.env.example'
        env_files = list(extract_path.rglob('.env*'))
        
        if not env_example.exists() and any('.env' in str(f) for f in env_files):
            self._add_issue(
                title="Missing .env.example",
                description="No .env.example template file",
                category="deployment",
                file="project-root",
                severity="low",
                solution="Add .env.example for documentation"
            )
            self.project_stats["deployment"]["config_issues"] += 1
    
    async def _check_dependency_vulnerabilities(self, extract_path: Path):
        """Check dependency vulnerabilities"""
        # Limited implementation for balanced performance
        pass
    
    async def _analyze_code_complexity_balanced(self, extract_path: Path):
        """Balanced code complexity analysis"""
        source_dirs = ['src', 'app', 'components']
        source_files = []
        
        for src_dir in source_dirs:
            src_path = extract_path / src_dir
            if src_path.exists():
                source_files.extend(list(src_path.rglob('*.js'))[:8])
                source_files.extend(list(src_path.rglob('*.jsx'))[:8])
                source_files.extend(list(src_path.rglob('*.ts'))[:8])
                source_files.extend(list(src_path.rglob('*.tsx'))[:8])
        
        source_files = source_files[:25]
        
        for file_path in source_files:
            try:
                complexity = self._calculate_complexity(file_path)
                if complexity > 50:
                    self._add_issue(
                        title="High Code Complexity",
                        description=f"Complexity score: {complexity}",
                        category="code_quality",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Refactor into smaller functions"
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
    
    async def _enhance_issues_with_llm(self, extract_path: Path) -> bool:
        """LLM enhancement"""
        if not self.issues or not self.llm_analyzer.enabled:
            return False
        
        critical_issues = [issue for issue in self.issues if issue.get('severity') == 'high'][:3]
        
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
                if enhanced_issue:
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
                return content[:2500]
        except Exception:
            pass
        return ""

    def _add_issue(self, title: str, description: str, category: str, file: str = "", 
                  severity: str = "medium", solution: str = ""):
        """Add issue"""
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
            "fix": solution,
            "timestamp": datetime.now().isoformat()
        })
    
    def _calculate_health_score(self) -> int:
        """Calculate health score"""
        base_score = 100
        
        for issue in self.issues:
            if issue['severity'] == 'high':
                base_score -= 8
            elif issue['severity'] == 'medium':
                base_score -= 4
            else:
                base_score -= 2
        
        return max(0, min(100, base_score))

    def _generate_summary(self) -> Dict:
        """Generate summary"""
        issue_count = len(self.issues)
        health_score = self._calculate_health_score()
        
        priority_breakdown = {1: 0, 2: 0, 3: 0}
        for issue in self.issues:
            if issue['severity'] == 'high':
                priority_breakdown[1] += 1
            elif issue['severity'] == 'medium':
                priority_breakdown[2] += 1
            else:
                priority_breakdown[3] += 1
        
        category_breakdown = {}
        for issue in self.issues:
            category = issue['category']
            category_breakdown[category] = category_breakdown.get(category, 0) + 1
        
        status = "healthy" if health_score >= 80 else "needs attention" if health_score >= 60 else "needs work"
        
        return {
            "total_issues": issue_count,
            "health_status": status,
            "health_score": health_score,
            "analysis_complete": not self.project_stats["performance"]["early_termination"],
            "priority_breakdown": priority_breakdown,
            "category_breakdown": category_breakdown,
        }
    
    async def _cleanup_directory(self, directory_path: Path):
        """Cleanup directory"""
        try:
            if directory_path.exists():
                def remove_directory(path):
                    shutil.rmtree(path, ignore_errors=True)
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, remove_directory, directory_path)
        except Exception as e:
            print(f"Cleanup warning: {e}")

# Flask Routes (same as before, but using BalancedProjectAnalyzer)
@app.route('/')
def root():
    return jsonify({
        "message": "CodeCopilot API - Balanced Edition",
        "version": "2.0.0", 
        "status": "running",
        "llm_enabled": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "performance_optimized": True,
        "max_file_size": f"{MAX_FILE_SIZE // (1024*1024)}MB",
        "max_extracted_size": f"{MAX_EXTRACTED_SIZE // (1024*1024)}MB",
        "features": [
            "Dependency Analysis",
            "Security Scanning", 
            "Code Quality Checks",
            "Performance Analysis", 
            "AI-Powered Insights"
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
            "service": "codecopilot-backend-balanced",
            "version": "2.0.0",
            "llm_available": LLM_ENABLED,
            "llm_model_available": model_working,
            "performance": {
                "max_file_size_mb": MAX_FILE_SIZE // (1024*1024),
                "max_extracted_size_mb": MAX_EXTRACTED_SIZE // (1024*1024),
                "max_file_count": MAX_FILE_COUNT,
                "max_scan_files": MAX_SCAN_FILES
            }
        })
    except Exception as e:
        return jsonify({"status": "degraded", "error": str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_project():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.zip'):
        return jsonify({"error": "Please upload a ZIP file"}), 400
    
    temp_dir = Path(tempfile.mkdtemp())
    temp_file = temp_dir / SmartSecurityScanner.sanitize_filename(file.filename)
    
    try:
        file.save(temp_file)
        
        if temp_file.stat().st_size > MAX_FILE_SIZE:
            return jsonify({
                "error": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB.",
                "rejection_reason": "FILE_TOO_LARGE"
            }), 400
        
        if temp_file.stat().st_size == 0:
            return jsonify({"error": "File is empty"}), 400
        
        # Use balanced analyzer
        analyzer = BalancedProjectAnalyzer()
        results = asyncio.run(analyzer.analyze_project(temp_file))
        
        return jsonify(results)
        
    except ValueError as e:
        try:
            error_data = json.loads(str(e))
            return jsonify(error_data), 400
        except json.JSONDecodeError:
            return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Analysis failed"}), 500
    finally:
        try:
            if temp_file.exists():
                temp_file.unlink()
            if temp_dir.exists():
                temp_dir.rmdir()
        except Exception:
            pass

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    
    print(f"🚀 Starting Balanced CodeCopilot Backend on port {port}")
    print(f"📁 Max File Size: {MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"📦 Max Extracted Size: {MAX_EXTRACTED_SIZE // (1024*1024)}MB")
    print(f"📊 Max File Count: {MAX_FILE_COUNT:,} files")
    print(f"⚡ Balanced Performance: Enabled")
    
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)