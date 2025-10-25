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

# 🚀 RENDER-FRIENDLY PERFORMANCE CONSTANTS
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB (reduced from 400MB)
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200MB (reduced from 800MB)
MAX_FILE_COUNT = 10000  # Reduced from 50000
MAX_COMPRESSION_RATIO = 30  # Reduced from 50
MAX_DEPTH = 10  # Reduced from 20

# 🚀 RENDER-FRIENDLY PERFORMANCE SETTINGS
MAX_WORKERS = min(2, multiprocessing.cpu_count())  # Reduced from 4
BATCH_SIZE = 20  # Reduced from 50
MAX_SCAN_FILES = 2000  # Reduced from 10000
EARLY_RETURN_CRITICAL_ISSUES = 3  # Reduced from 5

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
            "gemini-2.0-flash",
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

class SecurityScanner:
    """Ultra-optimized security scanner for Render free tier"""
    
    # 🎯 SKIP THESE EXTENSIONS COMPLETELY (User can't change these)
    SKIP_EXTENSIONS = {
        # Executables
        '.bat', '.cmd', '.ps1', '.sh', '.scr', '.com', '.pif', '.msi',
        '.jar', '.war', '.apk', '.exe', '.dll', '.so', '.dylib',
        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        # Media files (large and irrelevant for code analysis)
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.mp3', '.wav', '.ogg', '.flac',
        '.pdf', '.doc', '.docx', '.ppt', '.pptx',
        # Fonts and other binaries
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.ico', '.icns'
    }
    
    # 🎯 FILES TO SCAN (Focus only on these)
    SCAN_EXTENSIONS = {
        '.json', '.yml', '.yaml', '.config.js', '.config.ts',
        '.env', '.env.example', '.env.local',
        '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
        '.html', '.htm', '.css', '.scss', '.sass', '.less',
        '.md', '.txt', '.xml',
    }
    
    SCAN_FILENAMES = {
        'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
        'dockerfile', '.dockerignore', 'docker-compose.yml',
        '.eslintrc', '.prettierrc', '.babelrc', 'tsconfig.json', 'webpack.config.js',
        'vite.config.js', 'vite.config.ts', 'rollup.config.js'
    }
    
    def __init__(self):
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
    
    def validate_and_extract_zip(self, zip_path: Path, extract_path: Path) -> Dict:
        """Ultra-optimized ZIP extraction for Render"""
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
        
        try:
            # Basic ZIP validation
            if not self._is_valid_zip(zip_path):
                return {"valid": False, "error": "This doesn't appear to be a valid ZIP file."}
            
            # Sequential bomb detection (reduced parallel overhead)
            bomb_check = self._sequential_detect_zip_bomb(zip_path)
            if not bomb_check["safe"]:
                return self._get_zip_bomb_error_message(bomb_check)
            
            extract_path.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Sequential extraction for reduced memory usage
                return self._sequential_extract_files(zip_ref, extract_path)
                
        except zipfile.BadZipFile:
            return {"valid": False, "error": "This file appears to be corrupted or not a valid ZIP file."}
        except Exception as e:
            return {"valid": False, "error": f"Failed to process your project: {str(e)}"}

    def _sequential_detect_zip_bomb(self, zip_path: Path) -> Dict:
        """Sequential zip bomb detection for reduced memory usage"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                total_files = 0
                total_uncompressed_size = 0
                max_compression_ratio = 0
                max_depth = 0
                
                for file_info in zip_ref.infolist():
                    # Check for path traversal
                    if '..' in file_info.filename or file_info.filename.startswith('/'):
                        return {"safe": False, "reason": "Path traversal attempt detected"}
                    
                    # Calculate directory depth
                    depth = file_info.filename.count('/') + file_info.filename.count('\\')
                    max_depth = max(max_depth, depth)
                    
                    if depth > MAX_DEPTH:
                        return {"safe": False, "reason": f"Excessive directory depth ({depth} levels)"}
                    
                    # Check compression ratio
                    if file_info.compress_size > 0:
                        ratio = file_info.file_size / file_info.compress_size
                        max_compression_ratio = max(max_compression_ratio, ratio)
                        
                        if ratio > MAX_COMPRESSION_RATIO:
                            return {"safe": False, "reason": f"Suspicious compression ratio ({ratio:.1f}:1) in {file_info.filename}"}
                    
                    total_files += 1
                    total_uncompressed_size += file_info.file_size
                    
                    # Early termination
                    if total_files > MAX_FILE_COUNT:
                        return {"safe": False, "reason": f"Too many files ({total_files} > {MAX_FILE_COUNT})"}
                    
                    if total_uncompressed_size > MAX_EXTRACTED_SIZE:
                        return {"safe": False, "reason": f"Total uncompressed size too large ({total_uncompressed_size // (1024*1024)}MB)"}
                
                return {"safe": True, "reason": "No threats detected"}
                
        except Exception as e:
            return {"safe": False, "reason": f"Security scan failed: {str(e)}"}

    def _sequential_extract_files(self, zip_ref, extract_path: Path) -> Dict:
        """Sequential file extraction for reduced memory usage"""
        extracted_size = 0
        extracted_files = 0
        
        for file_info in zip_ref.infolist():
            if extracted_files > MAX_FILE_COUNT:
                return {"valid": False, "error": "Too many files. Remove node_modules and large directories."}
            
            if extracted_size > MAX_EXTRACTED_SIZE:
                return {"valid": False, "error": "Project too large. Maximum size is 200MB."}
            
            if self._should_skip_file(file_info.filename):
                self.skipped_files.append(file_info.filename)
                continue
            
            # Extract the file
            try:
                zip_ref.extract(file_info, extract_path)
                extracted_files += 1
                extracted_size += file_info.file_size
            except Exception as e:
                print(f"Warning: Failed to extract {file_info.filename}: {e}")
        
        return {
            "valid": True,
            "skipped_files": self.skipped_files[:50],
            "total_skipped": len(self.skipped_files),
            "extracted_files": extracted_files,
            "extracted_size": extracted_size,
            "threats_detected": self.detected_threats
        }

    def _get_zip_bomb_error_message(self, bomb_check: Dict) -> Dict:
        """Return user-friendly zip bomb error messages"""
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
                "details": "This project has an unusually high number of files.",
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
        """Optimized ZIP validation"""
        return (file_path.suffix.lower() == '.zip' and 
                file_path.exists() and 
                file_path.stat().st_size > 0)

    def _should_skip_file(self, filename: str) -> bool:
        """Ultra-optimized file skipping for Render free tier"""
        file_path = Path(filename)
        file_ext = file_path.suffix.lower()
        filename_lower = filename.lower()
        
        # 🎯 Early return for skipped extensions
        if file_ext in self.SKIP_EXTENSIONS:
            return True
        
        # 🎯 Early return for skipped directories
        if any(skip_dir in filename_lower for skip_dir in SKIP_PATHS):
            return True
        
        # 🎯 Only scan files we actually care about
        if file_ext not in [ext for ext in self.SCAN_EXTENSIONS]:
            if file_path.name.lower() not in self.SCAN_FILENAMES:
                return True
        
        return False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

class LLMAnalyzer:
    """Optimized LLM analyzer for Render"""
    
    def __init__(self):
        self.enabled = LLM_ENABLED and gemini_model is not None
        print(f"🧠 LLM Analyzer initialized - Enabled: {self.enabled}")
    
    async def analyze_issues_batch(self, issues: List[Dict], code_contexts: Dict[str, str] = None) -> List[Dict]:
        """Batch process issues with LLM for better performance"""
        if not self.enabled or not issues:
            return issues
        
        # Limit LLM analysis to critical issues only for performance
        critical_issues = [issue for issue in issues if issue.get('severity') == 'high'][:3]  # Reduced from 5
        
        if not critical_issues:
            return issues
        
        try:
            # Process critical issues sequentially to reduce API load
            enhanced_issues = []
            for issue in critical_issues:
                enhanced_issue = await self.analyze_issue_with_llm(issue, code_contexts.get(issue.get('file', ''), ''))
                if enhanced_issue:
                    enhanced_issues.append(enhanced_issue)
            
            # Update original issues with enhanced versions
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
        """Optimized single issue analysis with timeout"""
        if not self.enabled:
            return issue
        
        try:
            prompt = self._build_analysis_prompt(issue, code_context)
            
            # Add timeout to prevent hanging
            response = await asyncio.wait_for(
                self._get_llm_response(prompt), 
                timeout=8.0  # Reduced from 10.0
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
        """Optimized prompt building"""
        return f"""
        As an expert web developer, analyze this code issue and provide detailed solutions.

        ISSUE:
        - Title: {issue['title']}
        - Description: {issue['description']}
        - Category: {issue['category']}
        - File: {issue.get('file', 'N/A')}
        - Severity: {issue.get('severity', 'medium')}

        CODE CONTEXT:
        {code_context[:1000] if code_context else 'No specific code context provided'}

        Please provide:
        1. Root cause explanation (1-2 sentences)
        2. Step-by-step solution (3-5 steps)
        3. Prevention tips (2-3 tips)

        Keep responses concise and actionable. Focus on practical solutions.
        """

    async def _get_llm_response(self, prompt: str) -> str:
        """Get LLM response with error handling"""
        if not self.enabled or not gemini_model:
            return ""
        
        try:
            response = gemini_model.generate_content(prompt)
            return response.text if response else ""
        except Exception as e:
            print(f"Gemini API error: {e}")
            return ""

    def _parse_llm_response(self, issue: Dict, llm_response: str) -> Dict:
        """Fast LLM response parsing"""
        if not llm_response.strip():
            issue["llm_enhanced"] = False
            return issue
        
        # Simple parsing - use the whole response as detailed solution
        issue.update({
            "llm_enhanced": True,
            "detailed_solution": llm_response.strip()[:800],  # Reduced from 1000
            "root_cause": "Analyzed by AI",
            "prevention": "See detailed solution above",
            "ai_analyzed": True
        })
        
        return issue

class ProjectAnalyzer:
    """Ultra-optimized project analyzer for Render free tier"""
    
    def __init__(self):
        self.issues = []
        self.project_stats = self._init_project_stats()
        self.security_scanner = SecurityScanner()
        self.llm_analyzer = LLMAnalyzer()
        self._critical_issue_count = 0
        self._files_scanned = 0
    
    def _init_project_stats(self):
        """Initialize comprehensive project stats"""
        return {
            "total_files": 0, "package_files": 0, "config_files": 0,
            "large_project": False, "node_modules_detected": False,
            "skipped_files": 0, "security_warnings": [], "threats_detected": [],
            "security_scan": {"vulnerable_deps": 0, "secrets_found": 0, "misconfigurations": 0},
            "code_quality": {"eslint_issues": 0, "typescript_issues": 0, "testing_issues": 0},
            "deployment": {"build_issues": 0, "config_issues": 0},
            "performance": {"scan_duration": 0, "files_processed": 0, "early_termination": False},
            "advanced_metrics": {
                "code_complexity": {"high_complexity_files": 0, "most_complex_files": []},
                "performance_issues": 0,
                "accessibility_issues": 0,
                "architecture_issues": 0,
                "code_metrics": {},
                "ci_cd_issues": 0
            }
        }
    
    async def analyze_project(self, zip_path: Path) -> Dict:
        """Ultra-optimized project analysis for Render"""
        start_time = datetime.now()
        self.issues = []
        self.project_stats = self._init_project_stats()
        self._critical_issue_count = 0
        self._files_scanned = 0
        
        extract_path = Path(tempfile.mkdtemp(prefix="codecopilot_"))
        
        try:
            # Extract with security scanning
            extract_result = self.security_scanner.validate_and_extract_zip(zip_path, extract_path)
            
            if not extract_result["valid"]:
                if "rejection_reason" in extract_result:
                    raise ValueError(json.dumps(extract_result))
                else:
                    raise ValueError(extract_result["error"])
            
            # Update stats from extraction
            self.project_stats["skipped_files"] = extract_result["total_skipped"]
            if extract_result["skipped_files"]:
                self.project_stats["security_warnings"].append({
                    "type": "skipped_files",
                    "message": f"Skipped {extract_result['total_skipped']} potentially unsafe files",
                    "files": extract_result["skipped_files"][:10]  # Reduced from 10
                })
            
            # 🚀 OPTIMIZED SEQUENTIAL ANALYSIS
            await self._optimized_sequential_analysis(extract_path)
            
            # Check if this is a large project
            if self.project_stats["total_files"] > 500:  # Reduced from 1000
                self.project_stats["large_project"] = True
            
            # Early termination check
            if self._critical_issue_count >= EARLY_RETURN_CRITICAL_ISSUES:
                self.project_stats["performance"]["early_termination"] = True
                self._add_issue(
                    title="Analysis terminated early",
                    description=f"Stopped analysis after finding {self._critical_issue_count} critical issues for performance",
                    category="performance",
                    file="project-root",
                    severity="low",
                    solution="This is a performance optimization. Review the critical issues found so far."
                )
            
            # Enhanced analysis with LLM (non-blocking)
            llm_was_used = False
            if self.llm_analyzer.enabled and self.issues:
                llm_was_used = await self._enhance_issues_with_llm(extract_path)
                print(f"🧠 LLM Enhancement: {llm_was_used}")
            
            # Calculate performance metrics
            duration = (datetime.now() - start_time).total_seconds()
            self.project_stats["performance"]["scan_duration"] = duration
            self.project_stats["performance"]["files_processed"] = self._files_scanned
            
            return {
                "timestamp": datetime.now().isoformat(),
                "issues": self.issues[:50],  # Reduced from 100
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
                    "critical_issues_found": self._critical_issue_count
                }
            }
        finally:
            await self._cleanup_directory(extract_path)
    
    async def _optimized_sequential_analysis(self, extract_path: Path):
        """Run optimized sequential analysis for Render"""
        # 🎯 CORE ANALYSIS (run these first sequentially)
        await self._fast_count_files(extract_path)
        await self._analyze_package_files_sequential(extract_path)
        await self._check_security_issues_focused(extract_path)
        
        # 🎯 SECONDARY ANALYSIS (only if core passes and project is small)
        if self._critical_issue_count < 3 and self.project_stats["total_files"] < 1000:
            await self._check_code_quality_focused(extract_path)
            await self._check_deployment_basic(extract_path)
            
            # 🎯 LIMITED ADVANCED FEATURES (only for very small projects)
            if self.project_stats["total_files"] < 300:
                await self._check_dependency_vulnerabilities(extract_path)
                await self._analyze_code_complexity_focused(extract_path)
    
    async def _fast_count_files(self, extract_path: Path):
        """Optimized file counting"""
        file_count = 0
        node_modules_detected = False
        
        try:
            for root, dirs, files in os.walk(extract_path):
                # Skip unwanted directories early
                dirs[:] = [d for d in dirs if d not in SKIP_PATHS]
                
                # Check if we're in node_modules
                if 'node_modules' in root:
                    node_modules_detected = True
                    dirs.clear()  # Skip traversing deeper
                    continue
                    
                file_count += len(files)
                
                # Early termination for very large projects
                if file_count > MAX_SCAN_FILES:
                    break
            
            self.project_stats["total_files"] = file_count
            self.project_stats["node_modules_detected"] = node_modules_detected
            self._files_scanned = file_count
            
        except Exception as e:
            print(f"Error counting files: {e}")
            self.project_stats["total_files"] = 0
            self._files_scanned = 0
    
    async def _analyze_package_files_sequential(self, extract_path: Path):
        """Sequential package.json analysis to reduce memory usage"""
        package_files = list(extract_path.rglob('package.json'))
        
        # Filter out node_modules packages
        package_files = [pf for pf in package_files if 'node_modules' not in str(pf)]
        
        if not package_files:
            return
        
        self.project_stats["package_files"] = len(package_files)
        
        # 🎯 Sequential processing instead of parallel
        for package_file in package_files[:3]:  # Limit to 3 package.json files
            self._analyze_single_package(package_file)
    
    def _analyze_single_package(self, package_file: Path):
        """Analyze a single package.json file"""
        try:
            with open(package_file, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
            
            # Run essential package checks only
            self._check_socket_versions(package_data, package_file)
            self._check_dependencies(package_data, package_file)
            self._check_peer_dependencies(package_data, package_file)
            self._check_scripts(package_data, package_file)
            self._check_vulnerable_dependencies(package_data, package_file)
            
        except json.JSONDecodeError as e:
            self._add_issue(
                title="Invalid package.json",
                description=f"The package.json file contains invalid JSON syntax.",
                category="configuration",
                file=str(package_file.relative_to(package_file.parent.parent)),
                severity="high"
            )
        except Exception as e:
            print(f"Error analyzing package.json {package_file}: {e}")
    
    def _check_socket_versions(self, package_data: Dict, package_file: Path):
        """Check for socket.io version mismatches"""
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        if 'socket.io' in dependencies and 'socket.io-client' in dependencies:
            server_version = dependencies['socket.io']
            client_version = dependencies['socket.io-client']
            
            if server_version != client_version:
                self._add_issue(
                    title="Socket.io Version Mismatch",
                    description=f"Socket.io server version ({server_version}) doesn't match client version ({client_version})",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="medium",
                    solution="Ensure socket.io and socket.io-client versions match for compatibility"
                )
    
    def _check_dependencies(self, package_data: Dict, package_file: Path):
        """Check for common dependency issues"""
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        # Check React version consistency
        if 'react' in dependencies and 'react-dom' in dependencies:
            react_version = dependencies['react']
            react_dom_version = dependencies['react-dom']
            
            if react_version != react_dom_version:
                self._add_issue(
                    title="React Version Mismatch",
                    description=f"React version ({react_version}) doesn't match ReactDOM version ({react_dom_version})",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="medium",
                    solution="Ensure react and react-dom versions match for compatibility"
                )
    
    def _check_peer_dependencies(self, package_data: Dict, package_file: Path):
        """Check for missing peer dependencies"""
        peer_dependencies = package_data.get('peerDependencies', {})
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        for peer_dep, version in peer_dependencies.items():
            if peer_dep not in dependencies:
                self._add_issue(
                    title="Missing Peer Dependency",
                    description=f"Peer dependency {peer_dep} is not installed",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="high",
                    solution=f"Install {peer_dep} as a dependency or devDependency"
                )
    
    def _check_scripts(self, package_data: Dict, package_file: Path):
        """Check package.json scripts for issues"""
        scripts = package_data.get('scripts', {})
        
        if 'start' not in scripts and 'dev' not in scripts:
            self._add_issue(
                title="Missing Start Script",
                description="No start or dev script found in package.json",
                category="configuration",
                file=str(package_file.relative_to(package_file.parent.parent)),
                severity="low",
                solution="Add a 'start' or 'dev' script to run your application"
            )
    
    def _check_vulnerable_dependencies(self, package_data: Dict, package_file: Path):
        """Check for dependencies with known vulnerabilities"""
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        for dep, version in dependencies.items():
            if dep in VULNERABLE_PATTERNS:
                vulnerable_version = VULNERABLE_PATTERNS[dep]
                self._add_issue(
                    title=f"Vulnerable Dependency: {dep}",
                    description=f"{dep} version {version} may have known vulnerabilities. Affected versions: {vulnerable_version}",
                    category="security",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="high",
                    solution=f"Update {dep} to a secure version above {vulnerable_version}"
                )
                self.project_stats["security_scan"]["vulnerable_deps"] += 1
    
    async def _check_security_issues_focused(self, extract_path: Path):
        """Focused security scanning"""
        # 🎯 Only check critical config files
        critical_configs = [
            extract_path / '.env',
            extract_path / '.env.local',
            extract_path / '.env.production',
        ]
        
        for config_file in critical_configs:
            if config_file.exists():
                self._scan_single_file_for_secrets(config_file)
    
    def _scan_single_file_for_secrets(self, file_path: Path) -> int:
        """Scan a single file for secrets"""
        secrets_found = 0
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            for pattern, secret_type in SECRET_PATTERNS.items():
                if pattern.search(content):
                    secrets_found += 1
                    self._add_issue(
                        title=f"Hardcoded {secret_type} Found",
                        description=f"Potential {secret_type.lower()} found in configuration file",
                        category="security",
                        file=str(file_path.relative_to(file_path.parent.parent.parent)),
                        severity="high",
                        solution=f"Move {secret_type.lower()} to environment variables or secure secret management system"
                    )
                    
                    # Early return if we found too many secrets
                    if secrets_found >= 3:  # Reduced from 5
                        break
                        
        except Exception:
            pass
        
        return secrets_found
    
    async def _check_code_quality_focused(self, extract_path: Path):
        """Focused code quality checks"""
        # Run essential code quality checks only
        await self._check_eslint_config(extract_path)
        await self._check_typescript_config(extract_path)
        await self._check_testing_setup(extract_path)
    
    async def _check_eslint_config(self, extract_path: Path):
        """Check ESLint configuration"""
        eslint_configs = list(extract_path.rglob('.eslintrc*')) + \
                        list(extract_path.rglob('eslint.config.js'))
        
        if not eslint_configs:
            self._add_issue(
                title="No ESLint Configuration Found",
                description="Project doesn't have ESLint configured for code quality",
                category="code_quality",
                file="project-root",
                severity="low",
                solution="Add ESLint configuration to enforce code quality standards"
            )
            self.project_stats["code_quality"]["eslint_issues"] += 1
    
    async def _check_typescript_config(self, extract_path: Path):
        """Check TypeScript configuration"""
        tsconfig_files = list(extract_path.rglob('tsconfig.json'))
        
        if tsconfig_files:
            for tsconfig in tsconfig_files[:1]:  # Only check first tsconfig
                try:
                    with open(tsconfig, 'r') as f:
                        tsconfig_data = json.load(f)
                    
                    # Check for strict mode
                    compiler_options = tsconfig_data.get('compilerOptions', {})
                    if not compiler_options.get('strict'):
                        self._add_issue(
                            title="TypeScript Strict Mode Disabled",
                            description="TypeScript strict mode is not enabled",
                            category="code_quality",
                            file=str(tsconfig.relative_to(extract_path)),
                            severity="medium",
                            solution="Enable strict mode in tsconfig.json for better type safety"
                        )
                        self.project_stats["code_quality"]["typescript_issues"] += 1
                        
                except Exception as e:
                    print(f"Error reading tsconfig.json: {e}")
    
    async def _check_testing_setup(self, extract_path: Path):
        """Check testing framework setup"""
        test_files = list(extract_path.rglob('*.test.js')) + \
                    list(extract_path.rglob('*.spec.js')) + \
                    list(extract_path.rglob('*.test.ts')) + \
                    list(extract_path.rglob('*.spec.ts'))
        
        if not test_files:
            self._add_issue(
                title="No Test Files Found",
                description="Project doesn't appear to have any test files",
                category="code_quality",
                file="project-root",
                severity="low",
                solution="Add test files to ensure code reliability"
            )
            self.project_stats["code_quality"]["testing_issues"] += 1
    
    async def _check_deployment_basic(self, extract_path: Path):
        """Basic deployment checks"""
        await self._check_build_configurations(extract_path)
        await self._check_environment_configs(extract_path)
    
    async def _check_build_configurations(self, extract_path: Path):
        """Check build configurations"""
        build_configs = list(extract_path.rglob('webpack.config.js')) + \
                       list(extract_path.rglob('vite.config.js')) + \
                       list(extract_path.rglob('vite.config.ts')) + \
                       list(extract_path.rglob('rollup.config.js'))
        
        if not build_configs:
            self._add_issue(
                title="No Build Configuration Found",
                description="Project doesn't have a build tool configuration",
                category="deployment",
                file="project-root",
                severity="low",
                solution="Configure a build tool like Webpack or Vite for production builds"
            )
            self.project_stats["deployment"]["build_issues"] += 1
    
    async def _check_environment_configs(self, extract_path: Path):
        """Check environment configurations"""
        env_example = extract_path / '.env.example'
        env_files = list(extract_path.rglob('.env*'))
        
        if not env_example.exists() and any('.env' in str(f) for f in env_files):
            self._add_issue(
                title="Missing .env.example File",
                description="Project has environment files but no .env.example template",
                category="deployment",
                file="project-root",
                severity="low",
                solution="Add a .env.example file with template variables for documentation"
            )
            self.project_stats["deployment"]["config_issues"] += 1
    
    async def _check_dependency_vulnerabilities(self, extract_path: Path):
        """Check for known security vulnerabilities in dependencies"""
        package_files = list(extract_path.rglob('package.json'))
        
        for package_file in package_files[:2]:  # Limit to 2 package files
            if 'node_modules' in str(package_file):
                continue
                
            try:
                with open(package_file, 'r') as f:
                    package_data = json.load(f)
                
                dependencies = {**package_data.get('dependencies', {}), 
                              **package_data.get('devDependencies', {})}
                
                # Enhanced vulnerability checking
                for dep, version in dependencies.items():
                    vuln_info = self._check_enhanced_vulnerability(dep, version)
                    if vuln_info.get('vulnerable'):
                        self._add_issue(
                            title=f"Vulnerable Dependency: {dep}",
                            description=f"Version {version} has known security vulnerabilities: {vuln_info.get('details', 'Unknown')}",
                            category="security",
                            file=str(package_file.relative_to(extract_path)),
                            severity="high",
                            solution=f"Update {dep} to version {vuln_info.get('safe_version', 'latest')}"
                        )
                        self.project_stats["security_scan"]["vulnerable_deps"] += 1
                        
            except Exception as e:
                print(f"Error checking vulnerabilities: {e}")
    
    def _check_enhanced_vulnerability(self, dep: str, version: str) -> Dict:
        """Enhanced vulnerability checking with more patterns"""
        extended_vulnerabilities = {
            'lodash': {'versions': '<4.17.21', 'details': 'Prototype pollution vulnerability'},
            'hoek': {'versions': '<4.2.1', 'details': 'Prototype pollution vulnerability'},
            'minimist': {'versions': '<1.2.6', 'details': 'Prototype pollution vulnerability'},
            'axios': {'versions': '<1.6.0', 'details': 'SSRF vulnerability'},
            'moment': {'versions': '<2.29.4', 'details': 'Regular expression DoS vulnerability'},
            'express': {'versions': '<4.18.0', 'details': 'Potential Open Redirect vulnerability'},
        }
        
        if dep in extended_vulnerabilities:
            vuln_info = extended_vulnerabilities[dep]
            # Simple version comparison
            if self._is_vulnerable_version(version, vuln_info['versions']):
                return {
                    'vulnerable': True,
                    'details': vuln_info['details'],
                    'safe_version': 'latest'
                }
        
        return {'vulnerable': False}
    
    def _is_vulnerable_version(self, current_version: str, vulnerable_range: str) -> bool:
        """Simple version vulnerability check"""
        try:
            current_clean = re.sub(r'[^0-9.]', '', current_version)
            if vulnerable_range.startswith('<'):
                range_clean = re.sub(r'[^0-9.]', '', vulnerable_range[1:])
                return float(current_clean) < float(range_clean)
        except:
            pass
        return False
    
    async def _analyze_code_complexity_focused(self, extract_path: Path):
        """Focused code complexity analysis"""
        # 🎯 Only analyze source files in src/ directory
        source_dirs = ['src', 'app', 'components', 'pages']
        source_files = []
        
        for src_dir in source_dirs:
            src_path = extract_path / src_dir
            if src_path.exists():
                source_files.extend(list(src_path.rglob('*.js'))[:5])  # Limit per directory
                source_files.extend(list(src_path.rglob('*.jsx'))[:5])
                source_files.extend(list(src_path.rglob('*.ts'))[:5])
                source_files.extend(list(src_path.rglob('*.tsx'))[:5])
        
        # 🎯 Limit total files analyzed
        source_files = source_files[:20]  # Reduced from 50
        
        for file_path in source_files:
            try:
                complexity = self._calculate_file_complexity(file_path)
                if complexity > 50:
                    self._add_issue(
                        title="High Code Complexity",
                        description=f"File has high complexity score ({complexity}) - consider refactoring",
                        category="code_quality",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Consider refactoring into smaller functions or modules"
                    )
                    self.project_stats["advanced_metrics"]["code_complexity"]["high_complexity_files"] += 1
            except Exception:
                continue
    
    def _calculate_file_complexity(self, file_path: Path) -> int:
        """Calculate cyclomatic complexity of a file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Enhanced complexity metrics
            complexity_score = 0
            complexity_score += content.count('if ')
            complexity_score += content.count('for ')
            complexity_score += content.count('while ')
            complexity_score += content.count('catch ')
            complexity_score += content.count('switch ')
            complexity_score += content.count('&&')
            complexity_score += content.count('||')
            complexity_score += content.count('? :')
            complexity_score += content.count('case ')
            
            return complexity_score
        except:
            return 0
    
    # 🧠 AI ENHANCEMENT METHODS
    
    async def _enhance_issues_with_llm(self, extract_path: Path) -> bool:
        """Batch LLM enhancement for better performance - returns True if any issues were enhanced"""
        if not self.issues or not self.llm_analyzer.enabled:
            return False
        
        # Only enhance critical issues for performance
        critical_issues = [issue for issue in self.issues if issue.get('severity') == 'high'][:2]  # Reduced from 3
        
        if not critical_issues:
            return False
        
        enhanced_count = 0
        
        try:
            # Get code contexts sequentially
            code_contexts = {}
            
            for issue in critical_issues:
                if 'file' in issue and issue['file'] != 'project-root':
                    content = await self._get_file_content_async(extract_path / issue['file'])
                    if content:
                        code_contexts[issue.get('file', '')] = content
            
            # Batch enhance issues
            enhanced_issues = await self.llm_analyzer.analyze_issues_batch(critical_issues, code_contexts)
            
            # Update issues list and count enhancements
            for i, enhanced_issue in enumerate(enhanced_issues):
                if enhanced_issue:
                    for j, original_issue in enumerate(self.issues):
                        if (original_issue['title'] == critical_issues[i]['title'] and 
                            original_issue['file'] == critical_issues[i]['file']):
                            self.issues[j] = enhanced_issue
                            enhanced_count += 1
                            break
            
        except Exception as e:
            print(f"Error in LLM enhancement: {e}")
            return False
        
        print(f"🧠 Enhanced {enhanced_count} issues with AI")
        return enhanced_count > 0

    async def _get_file_content_async(self, file_path: Path) -> str:
        """Async file reading for LLM context"""
        try:
            if file_path.exists() and file_path.is_file():
                # Use thread pool for file I/O
                loop = asyncio.get_event_loop()
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = await loop.run_in_executor(None, f.read)
                return content[:1500]  # Reduced from 2000
        except Exception:
            pass
        return ""

    def _add_issue(self, title: str, description: str, category: str, file: str = "", 
                  severity: str = "medium", solution: str = ""):
        """Optimized issue adding with critical issue tracking"""
        if severity == "high":
            self._critical_issue_count += 1
        
        # Map severity to priority
        severity_to_priority = {"high": 1, "medium": 2, "low": 3}
        
        self.issues.append({
            "title": title,
            "description": description,
            "category": category,
            "file": file,
            "severity": severity,
            "priority": severity_to_priority.get(severity, 2),
            "solution": solution,
            "fix": solution,
            "timestamp": datetime.now().isoformat()
        })
    
    def _calculate_health_score(self) -> int:
        """Optimized health score calculation"""
        base_score = 100
        
        for issue in self.issues:
            if issue['severity'] == 'high':
                base_score -= 10
            elif issue['severity'] == 'medium':
                base_score -= 5
            else:
                base_score -= 2
        
        # Bonus for good structure and configuration
        if self.project_stats["config_files"] > 2:
            base_score += 5
        if self.project_stats["security_scan"]["vulnerable_deps"] == 0:
            base_score += 5
        
        return max(0, min(100, base_score))

    def _generate_summary(self) -> Dict:
        """Optimized summary generation"""
        issue_count = len(self.issues)
        health_score = self._calculate_health_score()
        
        # Calculate priority breakdown
        priority_breakdown = {1: 0, 2: 0, 3: 0}
        for issue in self.issues:
            if issue['severity'] == 'high':
                priority_breakdown[1] += 1
            elif issue['severity'] == 'medium':
                priority_breakdown[2] += 1
            else:
                priority_breakdown[3] += 1
        
        # Calculate category breakdown
        category_breakdown = {}
        for issue in self.issues:
            category = issue['category']
            category_breakdown[category] = category_breakdown.get(category, 0) + 1
        
        if health_score >= 80:
            status = "healthy"
        elif health_score >= 60:
            status = "needs attention"
        else:
            status = "needs work"
        
        return {
            "total_issues": issue_count,
            "health_status": status,
            "health_score": health_score,
            "analysis_complete": not self.project_stats["performance"]["early_termination"],
            "priority_breakdown": priority_breakdown,
            "category_breakdown": category_breakdown,
            "security_scan": self.project_stats["security_scan"],
            "code_quality": self.project_stats["code_quality"],
            "deployment": self.project_stats["deployment"],
            "performance": self.project_stats["performance"]
        }
    
    async def _cleanup_directory(self, directory_path: Path):
        """Optimized directory cleanup"""
        try:
            if directory_path.exists():
                def remove_directory(path):
                    shutil.rmtree(path, ignore_errors=True)
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, remove_directory, directory_path)
        except Exception as e:
            print(f"⚠️ Warning: Failed to cleanup directory {directory_path}: {e}")

# Flask Routes
@app.route('/')
def root():
    return jsonify({
        "message": "CodeCopilot API - Render Optimized Edition",
        "version": "2.0.0",
        "status": "running",
        "llm_enabled": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "performance_optimized": True,
        "render_optimized": True,
        "parallel_workers": MAX_WORKERS,
        "early_termination": True,
        "max_scan_files": MAX_SCAN_FILES,
        "security": {
            "max_file_size": f"{MAX_FILE_SIZE // (1024*1024)}MB",
            "max_extracted_size": f"{MAX_EXTRACTED_SIZE // (1024*1024)}MB", 
            "max_file_count": MAX_FILE_COUNT,
            "max_compression_ratio": f"{MAX_COMPRESSION_RATIO}:1",
            "zip_bomb_protection": "Enabled"
        },
        "features": [
            "Dependency Analysis",
            "Security Scanning", 
            "Code Quality Checks",
            "Performance Analysis",
            "AI-Powered Insights"
        ],
        "endpoints": {
            "health": "/api/health",
            "analyze": "/api/analyze (POST)",
            "rules": "/api/rules"
        }
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint for monitoring and frontend status"""
    try:
        # Test LLM connectivity if enabled
        llm_status = "unknown"
        model_working = False
        
        if LLM_ENABLED and gemini_model:
            try:
                # Quick test to verify Gemini is working
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
            "service": "codecopilot-backend-render-optimized",
            "version": "2.0.0",
            "llm_available": LLM_ENABLED,
            "llm_model_available": model_working,
            "llm": {
                "available": LLM_ENABLED,
                "status": llm_status,
                "model_working": model_working
            },
            "performance": {
                "parallel_workers": MAX_WORKERS,
                "batch_size": BATCH_SIZE,
                "max_scan_files": MAX_SCAN_FILES,
                "early_return_threshold": EARLY_RETURN_CRITICAL_ISSUES,
                "max_file_size_mb": MAX_FILE_SIZE // (1024*1024),
                "max_extracted_size_mb": MAX_EXTRACTED_SIZE // (1024*1024),
                "max_file_count": MAX_FILE_COUNT,
                "max_compression_ratio": MAX_COMPRESSION_RATIO,
                "max_directory_depth": MAX_DEPTH
            },
            "security": {
                "zip_bomb_protection": True,
                "file_type_restrictions": True,
                "path_traversal_protection": True
            },
            "render_optimized": True,
            "system": {
                "python_version": os.sys.version,
                "platform": os.sys.platform
            }
        })
    except Exception as e:
        return jsonify({
            "status": "degraded",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "llm_available": False,
            "llm_model_available": False,
            "llm": {
                "available": False,
                "status": "check_failed",
                "model_working": False
            }
        }), 500

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_project():
    if 'file' not in request.files:
        return jsonify({
            "error": "No file provided",
            "rejection_reason": "NO_FILE",
            "user_tip": "Please select a ZIP file to analyze."
        }), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({
            "error": "No file selected",
            "rejection_reason": "EMPTY_FILE",
            "user_tip": "Please select a valid ZIP file."
        }), 400
    
    if not file.filename.endswith('.zip'):
        return jsonify({
            "error": "Please upload a ZIP file",
            "rejection_reason": "INVALID_FILE_TYPE",
            "user_tip": "Your project must be compressed as a .zip file."
        }), 400
    
    # Create secure temporary file
    temp_dir = Path(tempfile.mkdtemp())
    temp_file = temp_dir / SecurityScanner.sanitize_filename(file.filename)
    
    try:
        file.save(temp_file)
        
        # Validate file size
        if temp_file.stat().st_size > MAX_FILE_SIZE:
            return jsonify({
                "error": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB.",
                "rejection_reason": "FILE_TOO_LARGE",
                "details": f"Your file is {temp_file.stat().st_size // (1024*1024)}MB.",
                "user_tip": "Try removing large files like videos, images, or node_modules folder."
            }), 400
        
        # Check if file is empty
        if temp_file.stat().st_size == 0:
            return jsonify({
                "error": "File is empty",
                "rejection_reason": "EMPTY_ARCHIVE",
                "user_tip": "The ZIP file appears to be empty."
            }), 400
        
        # 🎯 ULTRA-OPTIMIZED ANALYSIS
        analyzer = ProjectAnalyzer()
        
        # Run analysis
        results = asyncio.run(analyzer.analyze_project(temp_file))
        
        return jsonify(results)
        
    except ValueError as e:
        try:
            # Try to parse as JSON for structured error
            error_data = json.loads(str(e))
            return jsonify(error_data), 400
        except json.JSONDecodeError:
            # Regular string error
            return jsonify({
                "error": str(e),
                "rejection_reason": "VALIDATION_ERROR",
                "user_tip": "Please check your ZIP file and try again."
            }), 400
            
    except Exception as e:
        app.logger.error(f"Analysis failed: {str(e)}")
        return jsonify({
            "error": "Analysis failed. Please try again.",
            "rejection_reason": "INTERNAL_ERROR",
            "user_tip": "This might be a temporary issue. Please try again in a few moments."
        }), 500
    finally:
        # Cleanup
        try:
            if temp_file.exists():
                temp_file.unlink()
            if temp_dir.exists():
                temp_dir.rmdir()
        except Exception as e:
            app.logger.warning(f"Cleanup failed: {e}")

@app.route('/api/rules')
def get_available_rules():
    return jsonify({
        "rules": [
            {
                "id": "socket_version_mismatch",
                "name": "Socket.io Version Mismatch",
                "description": "Checks if socket.io client and server versions match",
                "priority": 1
            },
            {
                "id": "react_version_mismatch", 
                "name": "React Version Mismatch",
                "description": "Checks if React and ReactDOM versions match",
                "priority": 2
            },
            {
                "id": "missing_peer_dependencies",
                "name": "Missing Peer Dependencies",
                "description": "Checks for missing peer dependencies",
                "priority": 2
            },
            {
                "id": "invalid_package_json",
                "name": "Invalid package.json",
                "description": "Validates package.json structure",
                "priority": 1
            },
            {
                "id": "missing_start_script", 
                "name": "Missing Start Script",
                "description": "Checks for missing start or dev scripts",
                "priority": 3
            },
            {
                "id": "vulnerable_dependencies",
                "name": "Vulnerable Dependencies",
                "description": "Checks for dependencies with known security vulnerabilities",
                "priority": 1
            },
            {
                "id": "hardcoded_secrets",
                "name": "Hardcoded Secrets",
                "description": "Scans for exposed API keys and credentials",
                "priority": 1
            },
            {
                "id": "eslint_configuration",
                "name": "ESLint Configuration",
                "description": "Checks for proper linting setup",
                "priority": 2
            },
            {
                "id": "typescript_strictness",
                "name": "TypeScript Strictness",
                "description": "Ensures TypeScript is properly configured for type safety",
                "priority": 2
            },
            {
                "id": "testing_setup",
                "name": "Testing Setup",
                "description": "Checks for testing framework and test files",
                "priority": 3
            },
            {
                "id": "build_configurations",
                "name": "Build Configurations",
                "description": "Checks for build tool setup",
                "priority": 2
            },
            {
                "id": "environment_configs",
                "name": "Environment Configurations",
                "description": "Validates environment variable management",
                "priority": 2
            }
        ],
        "llm_capabilities": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "render_optimized": True,
        "performance": {
            "parallel_processing": True,
            "batch_processing": True,
            "early_termination": True,
            "max_workers": MAX_WORKERS,
            "batch_size": BATCH_SIZE,
            "max_scan_files": MAX_SCAN_FILES,
            "early_return_threshold": EARLY_RETURN_CRITICAL_ISSUES
        },
        "security": {
            "zip_bomb_protection": True,
            "max_compression_ratio": MAX_COMPRESSION_RATIO,
            "max_directory_depth": MAX_DEPTH,
            "max_file_size_mb": MAX_FILE_SIZE // (1024*1024),
            "max_extracted_size_mb": MAX_EXTRACTED_SIZE // (1024*1024)
        }
    })

@app.errorhandler(413)
def too_large(e):
    return jsonify({
        "error": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB.",
        "rejection_reason": "FILE_TOO_LARGE",
        "user_tip": "Try compressing your project without large binary files or node_modules."
    }), 413

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded. Please try again later.",
        "rejection_reason": "RATE_LIMIT_EXCEEDED",
        "user_tip": "You can make up to 10 requests per minute. Please wait a moment and try again."
    }), 429

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    
    print(f"🚀 Starting Render-Optimized CodeCopilot Backend on port {port}")
    print(f"🧠 LLM Features: {'Enabled' if LLM_ENABLED else 'Disabled'}")
    if LLM_ENABLED:
        print(f"   Model Status: {'✅ Working' if gemini_model else '❌ Not Available'}")
    print(f"⚡ Render Optimizations: Enabled")
    print(f"   - Parallel Workers: {MAX_WORKERS}")
    print(f"   - Batch Size: {BATCH_SIZE}")
    print(f"   - Max Scan Files: {MAX_SCAN_FILES}")
    print(f"   - Early Termination: After {EARLY_RETURN_CRITICAL_ISSUES} critical issues")
    print(f"📁 Max File Size: {MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"📦 Max Extracted Size: {MAX_EXTRACTED_SIZE // (1024*1024)}MB") 
    print(f"📊 Max File Count: {MAX_FILE_COUNT:,} files")
    print(f"🛡️  Zip Bomb Protection: Enabled")
    print(f"🎯 Smart File Skipping: Enabled")
    print(f"   - Skip binaries, media, archives")
    print(f"   - Skip node_modules, build directories")
    print(f"   - Focus on source code and configs")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        threaded=True
    )