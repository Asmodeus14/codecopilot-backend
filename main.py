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

# 🚀 OPTIMIZED PERFORMANCE CONSTANTS
MAX_FILE_SIZE = 400 * 1024 * 1024
MAX_EXTRACTED_SIZE = 800 * 1024 * 1024
MAX_FILE_COUNT = 50000
MAX_COMPRESSION_RATIO = 50
MAX_DEPTH = 20

# 🚀 PERFORMANCE OPTIMIZATION SETTINGS
MAX_WORKERS = min(4, multiprocessing.cpu_count())
BATCH_SIZE = 50
MAX_SCAN_FILES = 10000
EARLY_RETURN_CRITICAL_ISSUES = 5

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
    '.nuxt', 'out', '.output', 'coverage', '.cache'
}

class SecurityScanner:
    """Optimized security scanner with parallel processing"""
    
    SKIP_EXTENSIONS = {
        '.bat', '.cmd', '.ps1', '.sh',
        '.scr', '.com', '.pif', '.msi',
        '.jar', '.war', '.apk',
    }
    
    ALLOW_IN_NODE_MODULES = {
        '.exe', '.dll', '.so', '.dylib',
    }
    
    def __init__(self):
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
    
    def validate_and_extract_zip(self, zip_path: Path, extract_path: Path) -> Dict:
        """Optimized ZIP extraction with parallel threat detection"""
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
        
        try:
            # Basic ZIP validation
            if not self._is_valid_zip(zip_path):
                return {"valid": False, "error": "This doesn't appear to be a valid ZIP file. Please make sure you're uploading a properly compressed project folder."}
            
            # Parallel bomb detection
            bomb_check = self._parallel_detect_zip_bomb(zip_path)
            if not bomb_check["safe"]:
                return self._get_zip_bomb_error_message(bomb_check)
            
            extract_path.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Batch extraction for better performance
                return self._batch_extract_files(zip_ref, extract_path)
                
        except zipfile.BadZipFile:
            return {"valid": False, "error": "This file appears to be corrupted or not a valid ZIP file. Please try creating a new ZIP file of your project."}
        except Exception as e:
            return {"valid": False, "error": f"Failed to process your project: {str(e)}"}

    def _parallel_detect_zip_bomb(self, zip_path: Path) -> Dict:
        """Parallel zip bomb detection for large archives"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_infos = list(zip_ref.infolist())
                
                # Process files in parallel batches
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    chunks = [file_infos[i:i + BATCH_SIZE] for i in range(0, len(file_infos), BATCH_SIZE)]
                    results = list(executor.map(self._analyze_file_chunk, chunks))
                
                # Aggregate results
                total_files = 0
                total_uncompressed_size = 0
                max_compression_ratio = 0
                max_depth = 0
                
                for chunk_result in results:
                    if not chunk_result["safe"]:
                        return chunk_result
                    
                    total_files += chunk_result["file_count"]
                    total_uncompressed_size += chunk_result["total_size"]
                    max_compression_ratio = max(max_compression_ratio, chunk_result["max_ratio"])
                    max_depth = max(max_depth, chunk_result["max_depth"])
                
                # Final checks
                if total_files > MAX_FILE_COUNT:
                    return {"safe": False, "reason": f"Too many files ({total_files} > {MAX_FILE_COUNT})"}
                
                if total_uncompressed_size > MAX_EXTRACTED_SIZE:
                    return {"safe": False, "reason": f"Total uncompressed size too large ({total_uncompressed_size // (1024*1024)}MB)"}
                
                if max_compression_ratio > MAX_COMPRESSION_RATIO:
                    return {"safe": False, "reason": f"Suspicious overall compression ratio ({max_compression_ratio:.1f}:1)"}
                
                return {"safe": True, "reason": "No threats detected"}
                
        except Exception as e:
            return {"safe": False, "reason": f"Security scan failed: {str(e)}"}

    def _analyze_file_chunk(self, file_chunk: List) -> Dict:
        """Analyze a chunk of files for zip bomb characteristics"""
        total_size = 0
        max_ratio = 0
        max_depth = 0
        
        for file_info in file_chunk:
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
                max_ratio = max(max_ratio, ratio)
                
                if ratio > MAX_COMPRESSION_RATIO:
                    return {"safe": False, "reason": f"Suspicious compression ratio ({ratio:.1f}:1) in {file_info.filename}"}
            
            total_size += file_info.file_size
        
        return {
            "safe": True,
            "file_count": len(file_chunk),
            "total_size": total_size,
            "max_ratio": max_ratio,
            "max_depth": max_depth
        }

    def _batch_extract_files(self, zip_ref, extract_path: Path) -> Dict:
        """Batch file extraction with early termination"""
        extracted_size = 0
        extracted_files = 0
        file_infos = []
        
        # Collect safe files first
        for file_info in zip_ref.infolist():
            if extracted_files > MAX_FILE_COUNT:
                return {"valid": False, "error": "This project contains too many files for analysis. Try removing the node_modules folder or splitting your project into smaller parts."}
            
            if extracted_size > MAX_EXTRACTED_SIZE:
                return {"valid": False, "error": "This project is too large to analyze safely. The maximum extracted size is 800MB. Try removing large files like videos, images, or node_modules."}
            
            if self._should_skip_file(file_info.filename):
                self.skipped_files.append(file_info.filename)
                continue
            
            file_infos.append(file_info)
            extracted_files += 1
            extracted_size += file_info.file_size
        
        # Extract in parallel batches
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            chunks = [file_infos[i:i + BATCH_SIZE] for i in range(0, len(file_infos), BATCH_SIZE)]
            
            for chunk in chunks:
                list(executor.map(
                    lambda fi: self._safe_extract_file(zip_ref, fi, extract_path),
                    chunk
                ))
        
        return {
            "valid": True,
            "skipped_files": self.skipped_files[:100],
            "total_skipped": len(self.skipped_files),
            "extracted_files": extracted_files,
            "extracted_size": extracted_size,
            "threats_detected": self.detected_threats
        }

    def _safe_extract_file(self, zip_ref, file_info, extract_path: Path):
        """Safely extract a single file"""
        try:
            zip_ref.extract(file_info, extract_path)
        except Exception as e:
            print(f"Warning: Failed to extract {file_info.filename}: {e}")

    def _get_zip_bomb_error_message(self, bomb_check: Dict) -> Dict:
        """Return user-friendly zip bomb error messages"""
        reason = bomb_check["reason"]
        
        if "compression ratio" in reason.lower():
            return {
                "valid": False,
                "error": "Suspicious compression detected",
                "details": "This file compresses too efficiently, which could indicate a security risk. Legitimate projects typically have compression ratios under 50:1.",
                "user_tip": "This is usually caused by test files with repeated patterns. Try zipping only your source code, not generated files.",
                "rejection_reason": "HIGH_COMPRESSION_RATIO"
            }
        elif "too many files" in reason.lower():
            return {
                "valid": False,
                "error": "Project contains too many files",
                "details": "This project has an unusually high number of files, which could overwhelm the analysis system.",
                "user_tip": "Try removing the node_modules folder before zipping. Most projects work fine without it for analysis.",
                "rejection_reason": "TOO_MANY_FILES"
            }
        elif "path traversal" in reason.lower():
            return {
                "valid": False,
                "error": "Invalid file paths detected",
                "details": "Some files in your project use paths that could access files outside your project folder.",
                "user_tip": "Re-zip your project from inside the project folder using: 'cd my-project && zip -r ../project.zip .'",
                "rejection_reason": "PATH_TRAVERSAL_ATTEMPT"
            }
        elif "directory depth" in reason.lower():
            return {
                "valid": False,
                "error": "Excessive directory depth",
                "details": "The project folder structure is too deeply nested, which could indicate malicious content.",
                "user_tip": "Simplify your project structure and re-zip the project.",
                "rejection_reason": "EXCESSIVE_DEPTH"
            }
        else:
            return {
                "valid": False,
                "error": "Security check failed",
                "details": "This file exhibits characteristics that could pose a security risk to our analysis system.",
                "user_tip": "This is usually a false positive. Try creating a fresh ZIP file of your project source code.",
                "rejection_reason": "GENERAL_SECURITY_FAILURE"
            }

    def _is_valid_zip(self, file_path: Path) -> bool:
        """Optimized ZIP validation"""
        return (file_path.suffix.lower() == '.zip' and 
                file_path.exists() and 
                file_path.stat().st_size > 0)

    def _should_skip_file(self, filename: str) -> bool:
        """Optimized file skipping with early returns"""
        file_ext = Path(filename).suffix.lower()
        filename_lower = filename.lower()
        
        # Early returns for common cases
        if file_ext in self.SKIP_EXTENSIONS:
            return True
        
        if file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
            return True
        
        # Allow binaries in node_modules
        if file_ext in self.ALLOW_IN_NODE_MODULES:
            return 'node_modules/' not in filename_lower
        
        return False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

class LLMAnalyzer:
    """Optimized LLM analyzer with batch processing"""
    
    def __init__(self):
        self.enabled = LLM_ENABLED and gemini_model is not None
        print(f"🧠 LLM Analyzer initialized - Enabled: {self.enabled}, Model: {gemini_model is not None}")
    
    async def analyze_issues_batch(self, issues: List[Dict], code_contexts: Dict[str, str] = None) -> List[Dict]:
        """Batch process issues with LLM for better performance"""
        if not self.enabled or not issues:
            return issues
        
        # Limit LLM analysis to critical issues only for performance
        critical_issues = [issue for issue in issues if issue.get('severity') == 'high'][:5]
        
        if not critical_issues:
            return issues
        
        try:
            # Process critical issues in parallel
            tasks = [self.analyze_issue_with_llm(issue, code_contexts.get(issue.get('file', ''), '')) 
                    for issue in critical_issues]
            
            enhanced_issues = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Update original issues with enhanced versions
            result_issues = issues.copy()
            for i, enhanced_issue in enumerate(enhanced_issues):
                if not isinstance(enhanced_issue, Exception) and enhanced_issue:
                    # Find and replace the original issue
                    for j, original_issue in enumerate(result_issues):
                        if (original_issue['title'] == critical_issues[i]['title'] and 
                            original_issue['file'] == critical_issues[i]['file']):
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
                timeout=10.0
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
        {code_context[:1500] if code_context else 'No specific code context provided'}

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
        
        # Parse the LLM response to extract different sections
        lines = llm_response.strip().split('\n')
        root_cause = ""
        detailed_solution = ""
        prevention = ""
        
        current_section = ""
        for line in lines:
            line_lower = line.lower()
            if 'root cause' in line_lower:
                current_section = 'root_cause'
                root_cause = line.split(':', 1)[-1].strip() if ':' in line else ""
            elif 'solution' in line_lower or 'step' in line_lower:
                current_section = 'solution'
                if not detailed_solution:
                    detailed_solution = line.split(':', 1)[-1].strip() if ':' in line else line
                else:
                    detailed_solution += "\n" + line
            elif 'prevention' in line_lower or 'prevent' in line_lower:
                current_section = 'prevention'
                prevention = line.split(':', 1)[-1].strip() if ':' in line else line
            else:
                if current_section == 'root_cause':
                    root_cause += " " + line.strip()
                elif current_section == 'solution':
                    detailed_solution += "\n" + line
                elif current_section == 'prevention':
                    prevention += " " + line.strip()
        
        # If we couldn't parse sections, use the whole response as detailed solution
        if not detailed_solution:
            detailed_solution = llm_response.strip()
        
        issue.update({
            "llm_enhanced": True,
            "detailed_solution": detailed_solution[:1000],
            "root_cause": root_cause[:500] if root_cause else "Analyzed by AI",
            "prevention": prevention[:500] if prevention else "See detailed solution above",
            "ai_analyzed": True
        })
        
        return issue

class ProjectAnalyzer:
    """Advanced project analyzer with comprehensive feature set"""
    
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
        """Comprehensive project analysis with all features"""
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
                    "files": extract_result["skipped_files"][:10]
                })
            
            # 🚀 COMPREHENSIVE PARALLEL ANALYSIS
            await self._comprehensive_parallel_analysis(extract_path)
            
            # Check if this is a large project
            if self.project_stats["total_files"] > 1000:
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
                print(f"🧠 LLM Enhancement: {llm_was_used} (enabled: {self.llm_analyzer.enabled}, issues: {len(self.issues)})")
            
            # Calculate performance metrics
            duration = (datetime.now() - start_time).total_seconds()
            self.project_stats["performance"]["scan_duration"] = duration
            self.project_stats["performance"]["files_processed"] = self._files_scanned
            
            return {
                "timestamp": datetime.now().isoformat(),
                "issues": self.issues[:100],
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
    
    async def _comprehensive_parallel_analysis(self, extract_path: Path):
        """Run all analysis tasks in parallel"""
        # 🎯 ALL ANALYSIS TASKS RUN CONCURRENTLY
        analysis_tasks = [
            # Core Analysis
            self._fast_count_files(extract_path),
            self._analyze_package_files_parallel(extract_path),
            self._check_security_issues_parallel(extract_path),
            self._check_code_quality_parallel(extract_path),
            self._check_deployment_parallel(extract_path),
            self._analyze_tech_stack(extract_path),
            self._analyze_project_size(extract_path),
            self._check_project_structure(extract_path),
            self._check_configuration_files(extract_path),
            
            # 🆕 ADVANCED FEATURES
            self._check_dependency_vulnerabilities(extract_path),
            self._analyze_code_complexity(extract_path),
            self._analyze_performance_issues(extract_path),
            self._check_accessibility(extract_path),
            self._calculate_code_metrics(extract_path),
            self._analyze_architecture(extract_path),
            self._check_ci_cd_configuration(extract_path),
            self._advanced_security_scan(extract_path)
        ]
        
        await asyncio.gather(*analysis_tasks)
        
        # Generate AI suggestions after all analysis is complete
        await self._generate_improvement_suggestions()
    
    # 🔧 CORE ANALYSIS METHODS (Existing)
    async def _fast_count_files(self, extract_path: Path):
        """Optimized file counting with proper directory traversal"""
        file_count = 0
        node_modules_detected = False
        
        try:
            for root, dirs, files in os.walk(extract_path):
                # Skip unwanted directories early - modify dirs in place to prevent traversal
                dirs[:] = [d for d in dirs if d not in SKIP_PATHS]
                
                # Check if we're in node_modules
                if 'node_modules' in root:
                    node_modules_detected = True
                    # Skip traversing deeper into node_modules
                    dirs.clear()
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
            # Fallback: count all files without filtering
            try:
                all_files = list(extract_path.rglob('*'))
                file_count = len([f for f in all_files if f.is_file()])
                self.project_stats["total_files"] = file_count
                self._files_scanned = file_count
            except:
                self.project_stats["total_files"] = 0
                self._files_scanned = 0
    
    async def _analyze_package_files_parallel(self, extract_path: Path):
        """Parallel package.json analysis"""
        package_files = list(extract_path.rglob('package.json'))
        
        # Filter out node_modules packages
        package_files = [pf for pf in package_files if 'node_modules' not in str(pf)]
        
        if not package_files:
            return
        
        self.project_stats["package_files"] = len(package_files)
        
        # Analyze packages in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            list(executor.map(self._analyze_single_package, package_files))
    
    def _analyze_single_package(self, package_file: Path):
        """Analyze a single package.json file"""
        try:
            with open(package_file, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
            
            # Run all package checks
            self._check_socket_versions(package_data, package_file)
            self._check_dependencies(package_data, package_file)
            self._check_peer_dependencies(package_data, package_file)
            self._check_scripts(package_data, package_file)
            self._check_engines(package_data, package_file)
            self._check_vulnerable_dependencies(package_data, package_file)
            self._check_security_misconfigurations(package_data, package_file)
            
        except json.JSONDecodeError as e:
            self._add_issue(
                title="Invalid package.json",
                description=f"The package.json file at {package_file.relative_to(package_file.parent.parent)} contains invalid JSON syntax.",
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
        
        # Check for dangerous scripts
        dangerous_patterns = ['rm -rf', 'chmod 777', 'eval', 'curl | bash']
        for script_name, script_content in scripts.items():
            for pattern in dangerous_patterns:
                if pattern in script_content:
                    self._add_issue(
                        title="Potentially Dangerous Script",
                        description=f"Script '{script_name}' contains potentially dangerous command: {pattern}",
                        category="security",
                        file=str(package_file.relative_to(package_file.parent.parent)),
                        severity="high",
                        solution="Review and sanitize the script to remove dangerous commands"
                    )
    
    def _check_engines(self, package_data: Dict, package_file: Path):
        """Check Node.js engine requirements"""
        engines = package_data.get('engines', {})
        node_version = engines.get('node', '')
        
        if node_version:
            # Check if Node.js version is very old
            if any(old in node_version for old in ['0.', '4.', '6.', '8.']):
                self._add_issue(
                    title="Outdated Node.js Version",
                    description=f"Project requires outdated Node.js version: {node_version}",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="medium",
                    solution="Update to a supported Node.js version (14.x or higher recommended)"
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
    
    def _check_security_misconfigurations(self, package_data: Dict, package_file: Path):
        """Check for security misconfigurations in package.json"""
        config = package_data.get('config', {})
        
        # Check for insecure configurations
        if config.get('unsafe-perm') is True:
            self._add_issue(
                title="Insecure Configuration",
                description="package.json config has unsafe-perm set to true",
                category="security",
                file=str(package_file.relative_to(package_file.parent.parent)),
                severity="medium",
                solution="Avoid using unsafe-perm unless absolutely necessary"
            )
    
    async def _check_security_issues_parallel(self, extract_path: Path):
        """Parallel security scanning"""
        # Scan for secrets in parallel batches
        config_files = list(extract_path.rglob('.env*')) + \
                     list(extract_path.rglob('config.json')) + \
                     list(extract_path.rglob('settings.json')) + \
                     list(extract_path.rglob('constants.js'))
        
        # Limit scanning for large projects
        config_files = config_files[:1000]
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            chunks = [config_files[i:i + BATCH_SIZE] for i in range(0, len(config_files), BATCH_SIZE)]
            
            for chunk in chunks:
                results = list(executor.map(self._scan_single_file_for_secrets, chunk))
                
                # Aggregate results
                for secrets_found in results:
                    if secrets_found:
                        self.project_stats["security_scan"]["secrets_found"] += secrets_found
    
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
                    if secrets_found >= 5:
                        break
                        
        except Exception:
            pass
        
        return secrets_found
    
    async def _check_code_quality_parallel(self, extract_path: Path):
        """Parallel code quality checks"""
        # Run independent code quality checks concurrently
        quality_tasks = [
            self._check_eslint_config(extract_path),
            self._check_typescript_config(extract_path),
            self._check_testing_setup(extract_path),
            self._check_code_structure(extract_path)
        ]
        
        await asyncio.gather(*quality_tasks)
    
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
            for tsconfig in tsconfig_files:
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
    
    async def _check_code_structure(self, extract_path: Path):
        """Check code structure and organization"""
        # Check for proper src directory
        src_dir = extract_path / 'src'
        if not src_dir.exists():
            self._add_issue(
                title="No src Directory",
                description="Project doesn't have a standard src directory structure",
                category="code_quality",
                file="project-root",
                severity="low",
                solution="Consider organizing source code in a src directory"
            )
    
    async def _check_deployment_parallel(self, extract_path: Path):
        """Parallel deployment checks"""
        # Run independent deployment checks concurrently
        deployment_tasks = [
            self._check_build_configurations(extract_path),
            self._check_environment_configs(extract_path),
            self._check_deployment_files(extract_path)
        ]
        
        await asyncio.gather(*deployment_tasks)
    
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
    
    async def _check_deployment_files(self, extract_path: Path):
        """Check deployment configuration files"""
        docker_files = list(extract_path.rglob('Dockerfile')) + \
                      list(extract_path.rglob('docker-compose.yml'))
        
        if not docker_files:
            self._add_issue(
                title="No Docker Configuration",
                description="Project doesn't have Docker configuration for containerization",
                category="deployment",
                file="project-root",
                severity="low",
                solution="Consider adding Docker configuration for easier deployment"
            )
    
    async def _analyze_tech_stack(self, extract_path: Path):
        """Analyze technology stack and frameworks"""
        tech_stack = {
            "frontend": set(),
            "backend": set(),
            "build_tools": set(),
            "testing": set()
        }
        
        package_files = list(extract_path.rglob('package.json'))
        
        for package_file in package_files:
            if 'node_modules' in str(package_file):
                continue
                
            try:
                with open(package_file, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                
                dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
                
                # Frontend frameworks
                frontend_frameworks = {
                    'react': 'React', 'next': 'Next.js', 'vue': 'Vue.js', 
                    'angular': 'Angular', 'svelte': 'Svelte', '@angular/core': 'Angular'
                }
                
                # Backend frameworks
                backend_frameworks = {
                    'express': 'Express.js', 'koa': 'Koa', 'fastify': 'Fastify',
                    'nestjs': 'NestJS', 'socket.io': 'Socket.IO'
                }
                
                # Build tools
                build_tools = {
                    'webpack': 'Webpack', 'vite': 'Vite', 'rollup': 'Rollup',
                    'parcel': 'Parcel', 'esbuild': 'esbuild'
                }
                
                # Testing frameworks
                testing_tools = {
                    'jest': 'Jest', 'mocha': 'Mocha', 'jasmine': 'Jasmine',
                    'vitest': 'Vitest', '@testing-library/react': 'React Testing Library'
                }
                
                for dep, name in frontend_frameworks.items():
                    if dep in dependencies:
                        tech_stack["frontend"].add(name)
                
                for dep, name in backend_frameworks.items():
                    if dep in dependencies:
                        tech_stack["backend"].add(name)
                
                for dep, name in build_tools.items():
                    if dep in dependencies:
                        tech_stack["build_tools"].add(name)
                
                for dep, name in testing_tools.items():
                    if dep in dependencies:
                        tech_stack["testing"].add(name)
                        
            except Exception as e:
                continue
        
        # Convert sets to lists for JSON serialization
        self.project_stats["tech_stack"] = {
            category: list(frameworks) 
            for category, frameworks in tech_stack.items()
        }
    
    async def _analyze_project_size(self, extract_path: Path):
        """Analyze project size and structure"""
        size_info = {
            "total_size_bytes": 0,
            "source_files": 0,
            "asset_files": 0,
            "config_files": 0,
            "largest_files": []
        }
        
        try:
            file_sizes = []
            
            for file_path in extract_path.rglob('*'):
                if file_path.is_file():
                    # Skip node_modules and other large directories
                    if any(skip in str(file_path) for skip in SKIP_PATHS):
                        continue
                        
                    file_size = file_path.stat().st_size
                    size_info["total_size_bytes"] += file_size
                    file_sizes.append((file_path, file_size))
                    
                    # Categorize files
                    file_ext = file_path.suffix.lower()
                    file_name = file_path.name.lower()
                    
                    if file_ext in ['.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte']:
                        size_info["source_files"] += 1
                    elif file_ext in ['.json', '.yml', '.yaml', '.config.js', '.env']:
                        size_info["config_files"] += 1
                    elif file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico']:
                        size_info["asset_files"] += 1
            
            # Get top 5 largest files
            file_sizes.sort(key=lambda x: x[1], reverse=True)
            size_info["largest_files"] = [
                {
                    "path": str(file_path.relative_to(extract_path)),
                    "size_mb": round(size / (1024 * 1024), 2)
                }
                for file_path, size in file_sizes[:5]
            ]
            
            # Convert to MB
            size_info["total_size_mb"] = round(size_info["total_size_bytes"] / (1024 * 1024), 2)
            
        except Exception as e:
            print(f"Error analyzing project size: {e}")
        
        self.project_stats["size_analysis"] = size_info
    
    async def _check_project_structure(self, extract_path: Path):
        """Check project structure and organization"""
        # Check for common project structure issues
        readme_files = list(extract_path.rglob('README.md'))
        if not readme_files:
            self._add_issue(
                title="No README File",
                description="Project doesn't have a README.md file",
                category="documentation",
                file="project-root",
                severity="low",
                solution="Add a README.md file with project documentation"
            )
        
        # Check for gitignore
        gitignore_files = list(extract_path.rglob('.gitignore'))
        if not gitignore_files:
            self._add_issue(
                title="No .gitignore File",
                description="Project doesn't have a .gitignore file",
                category="configuration",
                file="project-root",
                severity="low",
                solution="Add a .gitignore file to exclude unnecessary files from version control"
            )
    
    async def _check_configuration_files(self, extract_path: Path):
        """Check for configuration files"""
        # This method can be expanded to check various config files
        pass
    
    # 🚀 ADVANCED FEATURES IMPLEMENTATION
    
    async def _check_dependency_vulnerabilities(self, extract_path: Path):
        """Check for known security vulnerabilities in dependencies"""
        package_files = list(extract_path.rglob('package.json'))
        
        for package_file in package_files:
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
        # Extended vulnerability database
        extended_vulnerabilities = {
            'lodash': {'versions': '<4.17.21', 'details': 'Prototype pollution vulnerability'},
            'hoek': {'versions': '<4.2.1', 'details': 'Prototype pollution vulnerability'},
            'minimist': {'versions': '<1.2.6', 'details': 'Prototype pollution vulnerability'},
            'axios': {'versions': '<1.6.0', 'details': 'SSRF vulnerability'},
            'moment': {'versions': '<2.29.4', 'details': 'Regular expression DoS vulnerability'},
            'express': {'versions': '<4.18.0', 'details': 'Potential Open Redirect vulnerability'},
            'react': {'versions': '<16.14.0', 'details': 'XSS vulnerability in development mode'},
            'webpack': {'versions': '<5.24.0', 'details': 'Path traversal vulnerability'}
        }
        
        if dep in extended_vulnerabilities:
            vuln_info = extended_vulnerabilities[dep]
            # Simple version comparison (in real implementation, use proper semver comparison)
            if self._is_vulnerable_version(version, vuln_info['versions']):
                return {
                    'vulnerable': True,
                    'details': vuln_info['details'],
                    'safe_version': 'latest'
                }
        
        return {'vulnerable': False}
    
    def _is_vulnerable_version(self, current_version: str, vulnerable_range: str) -> bool:
        """Simple version vulnerability check"""
        # This is a simplified implementation
        # In production, use proper semver comparison libraries
        try:
            # Remove non-numeric characters and compare
            current_clean = re.sub(r'[^0-9.]', '', current_version)
            if vulnerable_range.startswith('<'):
                range_clean = re.sub(r'[^0-9.]', '', vulnerable_range[1:])
                return float(current_clean) < float(range_clean)
        except:
            pass
        return False
    
    async def _analyze_code_complexity(self, extract_path: Path):
        """Analyze code complexity and maintainability"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        complex_files = []
        
        for file_path in source_files[:100]:  # Limit for performance
            try:
                complexity = self._calculate_file_complexity(file_path)
                if complexity > 50:  # High complexity threshold
                    complex_files.append({
                        'file': str(file_path.relative_to(extract_path)),
                        'complexity_score': complexity
                    })
                    self._add_issue(
                        title="High Code Complexity",
                        description=f"File has high complexity score ({complexity}) - consider refactoring",
                        category="code_quality",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Consider refactoring into smaller functions or modules, extract reusable components"
                    )
                    self.project_stats["advanced_metrics"]["code_complexity"]["high_complexity_files"] += 1
            except Exception:
                continue
        
        self.project_stats["advanced_metrics"]["code_complexity"]["most_complex_files"] = \
            sorted(complex_files, key=lambda x: x['complexity_score'], reverse=True)[:5]
    
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
            complexity_score += content.count('? :')  # Ternary operators
            complexity_score += content.count('case ')  # Switch cases
            
            return complexity_score
        except:
            return 0
    
    async def _analyze_performance_issues(self, extract_path: Path):
        """Check for common performance anti-patterns"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        performance_issue_count = 0
        
        for file_path in source_files[:200]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for common performance issues
                performance_issues = self._detect_performance_anti_patterns(content)
                
                for issue in performance_issues:
                    self._add_issue(
                        title=issue['title'],
                        description=issue['description'],
                        category="performance",
                        file=str(file_path.relative_to(extract_path)),
                        severity=issue['severity'],
                        solution=issue['solution']
                    )
                    performance_issue_count += 1
                    
            except Exception:
                continue
        
        self.project_stats["advanced_metrics"]["performance_issues"] = performance_issue_count
    
    def _detect_performance_anti_patterns(self, content: str) -> List[Dict]:
        """Detect performance anti-patterns in code"""
        issues = []
        
        # Large inline styles
        if re.search(r'style={{[^}]{100,}}}', content):
            issues.append({
                'title': "Large Inline Styles",
                'description': "Large inline styles can impact rendering performance",
                'severity': 'low',
                'solution': "Move styles to CSS classes or styled components"
            })
        
        # Missing keys in loops
        if re.search(r'\.map\s*\(\s*\(\s*\w+\s*\)\s*=>', content) and 'key=' not in content:
            issues.append({
                'title': "Missing React Keys",
                'description': "Array.map without keys can cause performance issues",
                'severity': 'medium',
                'solution': "Add unique key prop to list items"
            })
        
        # Inline function declarations in JSX
        if re.search(r'onClick={\(\) => [^}]+}', content):
            issues.append({
                'title': "Inline Function in JSX",
                'description': "Inline function declarations can cause unnecessary re-renders",
                'severity': 'medium',
                'solution': "Define functions outside JSX or use useCallback hook"
            })
        
        # Large components without memoization
        if len(content) > 1000 and 'React.memo' not in content and 'useMemo' not in content:
            issues.append({
                'title': "Large Component Without Memoization",
                'description': "Large components may benefit from memoization to prevent unnecessary re-renders",
                'severity': 'low',
                'solution': "Consider using React.memo or useMemo for optimization"
            })
        
        return issues
    
    async def _check_accessibility(self, extract_path: Path):
        """Check for accessibility issues in React components"""
        jsx_files = list(extract_path.rglob('*.jsx')) + list(extract_path.rglob('*.tsx'))
        
        accessibility_issue_count = 0
        
        for file_path in jsx_files[:100]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                a11y_issues = self._detect_accessibility_issues(content)
                
                for issue in a11y_issues:
                    self._add_issue(
                        title=issue['title'],
                        description=issue['description'],
                        category="accessibility",
                        file=str(file_path.relative_to(extract_path)),
                        severity=issue['severity'],
                        solution=issue['solution']
                    )
                    accessibility_issue_count += 1
                    
            except Exception:
                continue
        
        self.project_stats["advanced_metrics"]["accessibility_issues"] = accessibility_issue_count
    
    def _detect_accessibility_issues(self, content: str) -> List[Dict]:
        """Detect accessibility issues in JSX/TSX files"""
        issues = []
        
        # Missing alt attributes
        if re.search(r'<img[^>]*?(?<=\s)(?!(alt=))[^>]*?>', content):
            issues.append({
                'title': "Missing Alt Text",
                'description': "Image missing alt attribute for screen readers",
                'severity': 'medium',
                'solution': "Add descriptive alt text to all img tags"
            })
        
        # Missing form labels
        if re.search(r'<input[^>]*?(?!(aria-label=|aria-labelledby=|id=))[^>]*?>', content) and \
           not re.search(r'<label[^>]*?>.*?</label>', content):
            issues.append({
                'title': "Missing Form Label",
                'description': "Input field missing associated label",
                'severity': 'medium',
                'solution': "Add label with htmlFor attribute or use aria-label"
            })
        
        # Low color contrast warnings
        if re.search(r'color:\s*#[fF]{6}', content) or re.search(r'color:\s*white', content):
            issues.append({
                'title': "Potential Color Contrast Issue",
                'description': "White text may have low contrast on light backgrounds",
                'severity': 'low',
                'solution': "Ensure sufficient color contrast ratio (4.5:1 minimum)"
            })
        
        # Missing button types
        if re.search(r'<button[^>]*?(?!(type=))[^>]*?>', content):
            issues.append({
                'title': "Missing Button Type",
                'description': "Button missing type attribute",
                'severity': 'low',
                'solution': "Add type='button', 'submit', or 'reset' to buttons"
            })
        
        return issues
    
    async def _calculate_code_metrics(self, extract_path: Path):
        """Calculate comprehensive code quality metrics"""
        metrics = {
            "total_lines": 0,
            "comment_ratio": 0,
            "function_count": 0,
            "average_function_length": 0,
            "file_size_distribution": {"small": 0, "medium": 0, "large": 0},
            "import_count": 0,
            "export_count": 0
        }
        
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        total_lines = 0
        comment_lines = 0
        function_count = 0
        import_count = 0
        export_count = 0
        
        for file_path in source_files[:500]:  # Limit for performance
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                total_lines += len(lines)
                
                # Count comment lines
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith('//') or stripped.startswith('/*') or stripped.endswith('*/'):
                        comment_lines += 1
                
                # Count functions (simplified)
                content = ' '.join(lines)
                function_count += content.count('function ') + content.count('=> {')
                
                # Count imports/exports
                import_count += content.count('import ')
                export_count += content.count('export ')
                
                # File size categorization
                file_size = len(content)
                if file_size < 1000:
                    metrics["file_size_distribution"]["small"] += 1
                elif file_size < 10000:
                    metrics["file_size_distribution"]["medium"] += 1
                else:
                    metrics["file_size_distribution"]["large"] += 1
                    
            except Exception:
                continue
        
        metrics["total_lines"] = total_lines
        metrics["comment_ratio"] = round((comment_lines / total_lines * 100), 2) if total_lines > 0 else 0
        metrics["function_count"] = function_count
        metrics["average_function_length"] = round(total_lines / function_count, 2) if function_count > 0 else 0
        metrics["import_count"] = import_count
        metrics["export_count"] = export_count
        
        self.project_stats["advanced_metrics"]["code_metrics"] = metrics
    
    async def _analyze_architecture(self, extract_path: Path):
        """Analyze project architecture and patterns"""
        architecture_issues = []
        architecture_issue_count = 0
        
        # Check for proper separation of concerns
        if self._has_mixed_responsibilities(extract_path):
            architecture_issues.append("Mixed responsibilities detected in components")
            architecture_issue_count += 1
        
        # Check for proper hook usage
        hook_issues = await self._check_hook_usage(extract_path)
        architecture_issues.extend(hook_issues)
        architecture_issue_count += len(hook_issues)
        
        # Check for prop drilling
        if self._detect_prop_drilling(extract_path):
            architecture_issues.append("Potential prop drilling detected")
            architecture_issue_count += 1
        
        if architecture_issues:
            self._add_issue(
                title="Architecture Improvement Opportunities",
                description="Several architecture patterns could be improved",
                category="architecture",
                file="project-root",
                severity="low",
                solution="Consider: " + "; ".join(architecture_issues)
            )
        
        self.project_stats["advanced_metrics"]["architecture_issues"] = architecture_issue_count
    
    def _has_mixed_responsibilities(self, extract_path: Path) -> bool:
        """Check if components have mixed responsibilities"""
        # Simple heuristic: look for components that both fetch data and render UI
        source_files = list(extract_path.rglob('*.jsx')) + list(extract_path.rglob('*.tsx'))
        
        for file_path in source_files[:50]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                # Check for both data fetching and complex rendering
                if ('fetch(' in content or 'axios' in content) and ('<div' in content or '<span' in content):
                    if content.count('<') > 10:  # Has significant rendering
                        return True
            except:
                continue
        return False
    
    async def _check_hook_usage(self, extract_path: Path) -> List[str]:
        """Check for proper React hook usage"""
        hook_issues = []
        source_files = list(extract_path.rglob('*.jsx')) + list(extract_path.rglob('*.tsx'))
        
        for file_path in source_files[:50]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for conditional hooks
                if 'if (' in content and ('useState' in content or 'useEffect' in content):
                    hook_issues.append(f"Potential conditional hook usage in {file_path.name}")
                
                # Check for missing dependencies in useEffect
                if 'useEffect' in content and 'eslint-disable' not in content:
                    # Simple check for exhaustive deps
                    if 'useEffect(() => {' in content and '[]' in content:
                        # Might be missing dependencies
                        hook_issues.append(f"Potential missing useEffect dependencies in {file_path.name}")
                        
            except:
                continue
        
        return hook_issues
    
    def _detect_prop_drilling(self, extract_path: Path) -> bool:
        """Detect potential prop drilling patterns"""
        # Simple heuristic: look for components passing many props
        source_files = list(extract_path.rglob('*.jsx')) + list(extract_path.rglob('*.tsx'))
        
        for file_path in source_files[:50]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                # Count prop pass-through patterns
                prop_passing = re.findall(r'<\\w+\\s+[^>]*\\{[^}]*\\}[^>]*>', content)
                if len(prop_passing) > 3:
                    return True
            except:
                continue
        return False
    
    async def _check_ci_cd_configuration(self, extract_path: Path):
        """Check for CI/CD configuration and best practices"""
        ci_files = list(extract_path.rglob('.github/workflows/*.yml')) + \
                   list(extract_path.rglob('.gitlab-ci.yml')) + \
                   list(extract_path.rglob('azure-pipelines.yml'))
        
        ci_cd_issue_count = 0
        
        if not ci_files:
            self._add_issue(
                title="No CI/CD Configuration Found",
                description="Project doesn't have continuous integration setup",
                category="deployment",
                file="project-root",
                severity="medium",
                solution="Add CI/CD configuration for automated testing and deployment"
            )
            ci_cd_issue_count += 1
        else:
            # Check CI/CD best practices
            for ci_file in ci_files:
                issues_found = self._analyze_ci_file(ci_file, extract_path)
                ci_cd_issue_count += issues_found
        
        self.project_stats["advanced_metrics"]["ci_cd_issues"] = ci_cd_issue_count
    
    def _analyze_ci_file(self, ci_file: Path, extract_path: Path) -> int:
        """Analyze CI/CD configuration file for best practices"""
        issues_found = 0
        try:
            with open(ci_file, 'r') as f:
                content = f.read()
            
            # Check for security best practices
            if 'actions/checkout' in content and '@v2' in content:
                self._add_issue(
                    title="Outdated GitHub Action",
                    description="Using outdated actions/checkout@v2",
                    category="security",
                    file=str(ci_file.relative_to(extract_path)),
                    severity="low",
                    solution="Update to actions/checkout@v4 for security improvements"
                )
                issues_found += 1
            
            # Check for missing security scanning
            if 'security' not in content.lower() and 'scan' not in content.lower():
                self._add_issue(
                    title="Missing Security Scanning in CI/CD",
                    description="CI/CD pipeline doesn't include security scanning",
                    category="security",
                    file=str(ci_file.relative_to(extract_path)),
                    severity="medium",
                    solution="Add security scanning steps to your CI/CD pipeline"
                )
                issues_found += 1
                
        except Exception as e:
            print(f"Error analyzing CI file: {e}")
        
        return issues_found
    
    async def _advanced_security_scan(self, extract_path: Path):
        """Advanced security vulnerability scanning"""
        # Check for XSS vulnerabilities
        await self._check_xss_vulnerabilities(extract_path)
        
        # Check for SQL injection patterns
        await self._check_sql_injection(extract_path)
        
        # Check for insecure random number usage
        await self._check_insecure_random(extract_path)
    
    async def _check_xss_vulnerabilities(self, extract_path: Path):
        """Check for Cross-Site Scripting vulnerabilities"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        for file_path in source_files[:100]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Detect innerHTML usage
                if 'innerHTML' in content and 'dangerouslySetInnerHTML' not in content:
                    self._add_issue(
                        title="Potential XSS Vulnerability",
                        description="innerHTML usage can lead to XSS attacks",
                        category="security",
                        file=str(file_path.relative_to(extract_path)),
                        severity="high",
                        solution="Use textContent or properly sanitize HTML input"
                    )
                
                # Detect eval usage
                if 'eval(' in content:
                    self._add_issue(
                        title="Dangerous eval() Usage",
                        description="eval() can execute arbitrary code and is a security risk",
                        category="security",
                        file=str(file_path.relative_to(extract_path)),
                        severity="high",
                        solution="Avoid eval() and use safer alternatives like Function constructor or JSON.parse"
                    )
                    
            except Exception:
                continue
    
    async def _check_sql_injection(self, extract_path: Path):
        """Check for SQL injection patterns"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.ts'))
        
        for file_path in source_files[:100]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Look for string concatenation in SQL queries
                if any(db in content for db in ['mysql', 'pg', 'sqlite', 'sequelize']):
                    if re.search(r'`\\$\\{.*\\}`', content) or re.search(r'\\+\\s*\\w+\\s*\\+', content):
                        self._add_issue(
                            title="Potential SQL Injection",
                            description="String concatenation in SQL queries can lead to injection attacks",
                            category="security",
                            file=str(file_path.relative_to(extract_path)),
                            severity="high",
                            solution="Use parameterized queries or prepared statements"
                        )
                        
            except Exception:
                continue
    
    async def _check_insecure_random(self, extract_path: Path):
        """Check for insecure random number usage"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.ts'))
        
        for file_path in source_files[:100]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for Math.random() usage in security contexts
                if 'Math.random()' in content and any(ctx in content for ctx in ['password', 'token', 'secret', 'crypto']):
                    self._add_issue(
                        title="Insecure Random Number Generation",
                        description="Math.random() is not cryptographically secure",
                        category="security",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Use crypto.getRandomValues() for cryptographic purposes"
                    )
                    
            except Exception:
                continue
    
    # 🧠 AI ENHANCEMENT METHODS
    
    async def _generate_improvement_suggestions(self):
        """Generate AI-powered improvement suggestions"""
        if not self.llm_analyzer.enabled:
            return
        
        try:
            issues_summary = "\n".join([
                f"- {issue['title']} ({issue['severity']})" 
                for issue in self.issues[:10]  # Limit to top 10 issues
            ])
            
            prompt = f"""
            As an expert software architect, analyze this project based on the found issues and provide strategic improvement suggestions.
            
            PROJECT STATS:
            - Total Files: {self.project_stats.get('total_files', 0)}
            - Health Score: {self._calculate_health_score()}
            - Critical Issues: {len([i for i in self.issues if i.get('severity') == 'high'])}
            - Major Issues: {len([i for i in self.issues if i.get('severity') == 'medium'])}
            
            KEY ISSUES FOUND:
            {issues_summary}
            
            Please provide:
            1. 3 strategic recommendations for code quality improvement
            2. 2 suggestions for project structure optimization  
            3. 1 performance optimization tip
            
            Keep it concise and actionable. Focus on high-impact changes.
            """
            
            response = await self.llm_analyzer._get_llm_response(prompt)
            if response:
                self.project_stats["improvement_suggestions"] = response
                
        except Exception as e:
            print(f"Error generating improvement suggestions: {e}")
    
    async def _enhance_issues_with_llm(self, extract_path: Path) -> bool:
        """Batch LLM enhancement for better performance - returns True if any issues were enhanced"""
        if not self.issues or not self.llm_analyzer.enabled:
            return False
        
        # Only enhance critical issues for performance
        critical_issues = [issue for issue in self.issues if issue.get('severity') == 'high'][:3]
        
        if not critical_issues:
            return False
        
        enhanced_count = 0
        
        try:
            # Get code contexts in parallel
            code_contexts = {}
            tasks = []
            
            for issue in critical_issues:
                if 'file' in issue and issue['file'] != 'project-root':
                    tasks.append(self._get_file_content_async(extract_path / issue['file']))
                else:
                    tasks.append(asyncio.sleep(0))
            
            file_contents = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, content in enumerate(file_contents):
                if not isinstance(content, Exception) and content:
                    code_contexts[critical_issues[i].get('file', '')] = content
            
            # Batch enhance issues
            enhanced_issues = await self.llm_analyzer.analyze_issues_batch(critical_issues, code_contexts)
            
            # Update issues list and count enhancements
            for i, enhanced_issue in enumerate(enhanced_issues):
                if not isinstance(enhanced_issue, Exception) and enhanced_issue:
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
                return content[:2000]
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
        if self.project_stats["code_quality"]["testing_issues"] == 0:
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
            "performance": self.project_stats["performance"],
            "advanced_metrics": self.project_stats["advanced_metrics"]
        }
    
    async def _cleanup_directory(self, directory_path: Path):
        """Optimized directory cleanup"""
        try:
            if directory_path.exists():
                def remove_directory(path):
                    shutil.rmtree(path, ignore_errors=True)
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, remove_directory, directory_path)
                print(f"✅ Cleaned up temporary directory: {directory_path}")
        except Exception as e:
            print(f"⚠️ Warning: Failed to cleanup directory {directory_path}: {e}")

# Flask Routes
@app.route('/')
def root():
    return jsonify({
        "message": "CodeCopilot API - Advanced Edition",
        "version": "2.0.0",
        "status": "running",
        "llm_enabled": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "performance_optimized": True,
        "advanced_features": True,
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
            "Accessibility Scanning",
            "Architecture Review",
            "CI/CD Configuration Check",
            "AI-Powered Insights",
            "Advanced Vulnerability Detection",
            "Code Complexity Analysis"
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
            "service": "codecopilot-backend-advanced",
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
            "advanced_features": True,
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
            "user_tip": "Your project must be compressed as a .zip file. Most operating systems have built-in zip functionality."
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
                "details": f"Your file is {temp_file.stat().st_size // (1024*1024)}MB, but the maximum allowed is {MAX_FILE_SIZE // (1024*1024)}MB.",
                "user_tip": "Try removing large files like videos, images, or node_modules folder before zipping."
            }), 400
        
        # Check if file is empty
        if temp_file.stat().st_size == 0:
            return jsonify({
                "error": "File is empty",
                "rejection_reason": "EMPTY_ARCHIVE",
                "user_tip": "The ZIP file appears to be empty. Please check your project and try again."
            }), 400
        
        # 🎯 COMPREHENSIVE ANALYSIS
        analyzer = ProjectAnalyzer()
        
        # Run analysis - this calls the analyze_project method above
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
                "id": "outdated_node_version",
                "name": "Outdated Node.js Version",
                "description": "Checks for outdated Node.js engine requirements",
                "priority": 1
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
                "id": "security_misconfigurations",
                "name": "Security Misconfigurations",
                "description": "Checks for dangerous scripts and security issues",
                "priority": 2
            },
            {
                "id": "eslint_configuration",
                "name": "ESLint Configuration",
                "description": "Checks for proper linting setup and security rules",
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
                "description": "Checks for build tool setup and optimizations",
                "priority": 2
            },
            {
                "id": "environment_configs",
                "name": "Environment Configurations",
                "description": "Validates environment variable management",
                "priority": 2
            },
            {
                "id": "deployment_files",
                "name": "Deployment Files",
                "description": "Checks for Docker and deployment configurations",
                "priority": 3
            },
            # 🆕 ADVANCED RULES
            {
                "id": "code_complexity",
                "name": "Code Complexity",
                "description": "Analyzes code complexity and maintainability",
                "priority": 2
            },
            {
                "id": "performance_issues",
                "name": "Performance Issues",
                "description": "Detects performance anti-patterns",
                "priority": 2
            },
            {
                "id": "accessibility",
                "name": "Accessibility",
                "description": "Checks for accessibility issues",
                "priority": 3
            },
            {
                "id": "architecture",
                "name": "Architecture",
                "description": "Analyzes project architecture patterns",
                "priority": 2
            },
            {
                "id": "ci_cd_configuration",
                "name": "CI/CD Configuration",
                "description": "Checks CI/CD pipeline best practices",
                "priority": 3
            },
            {
                "id": "advanced_security",
                "name": "Advanced Security",
                "description": "Advanced security vulnerability scanning",
                "priority": 1
            }
        ],
        "llm_capabilities": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "advanced_features": True,
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
    
    print(f"🚀 Starting Advanced CodeCopilot Backend on port {port}")
    print(f"🧠 LLM Features: {'Enabled' if LLM_ENABLED else 'Disabled'}")
    if LLM_ENABLED:
        print(f"   Model Status: {'✅ Working' if gemini_model else '❌ Not Available'}")
    print(f"⚡ Performance Optimizations: Enabled")
    print(f"   - Parallel Workers: {MAX_WORKERS}")
    print(f"   - Batch Size: {BATCH_SIZE}")
    print(f"   - Max Scan Files: {MAX_SCAN_FILES}")
    print(f"   - Early Termination: After {EARLY_RETURN_CRITICAL_ISSUES} critical issues")
    print(f"📁 Max File Size: {MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"📦 Max Extracted Size: {MAX_EXTRACTED_SIZE // (1024*1024)}MB") 
    print(f"📊 Max File Count: {MAX_FILE_COUNT:,} files")
    print(f"🛡️  Zip Bomb Protection: Enabled")
    print(f"   - Max Compression Ratio: {MAX_COMPRESSION_RATIO}:1")
    print(f"   - Max Directory Depth: {MAX_DEPTH} levels")
    print(f"🔒 Enhanced Security Scanning: Enabled")
    print(f"📝 Code Quality Analysis: Enabled") 
    print(f"🚀 Deployment & Build Analysis: Enabled")
    print(f"🎯 ADVANCED FEATURES:")
    print(f"   - Dependency Vulnerability Scanning")
    print(f"   - Code Complexity Analysis") 
    print(f"   - Performance Issue Detection")
    print(f"   - Accessibility Checking")
    print(f"   - Architecture Analysis")
    print(f"   - CI/CD Configuration Review")
    print(f"   - Advanced Security Scanning")
    print(f"   - Comprehensive Code Metrics")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        threaded=True
    )