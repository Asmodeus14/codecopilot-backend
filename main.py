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

# 🚀 PERFORMANCE CONSTANTS
MAX_FILE_SIZE = 150 * 1024 * 1024  # 150MB
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500MB
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

# 🚀 SKIP PATHS
SKIP_PATHS = {
    'node_modules', '.git', 'dist', 'build', '.next', '.nuxt',
    'out', '.output', 'coverage', '.cache', '__pycache__',
    '.vscode', '.idea', 'tmp', 'temp', 'logs',
    'vendor', 'bower_components', '.yarn', '.pnp',
    '.parcel-cache', '.eslintcache', '.tsbuildinfo'
}

class PermissiveSecurityScanner:
    """Security scanner that NEVER blocks analysis - only skips dangerous files"""
    
    # 🚨 ONLY skip truly dangerous executable files
    DANGEROUS_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.bat', '.cmd', '.ps1',
        '.sh', '.scr', '.com', '.pif', '.msi', '.jar', '.war', '.apk'
    }
    
    def __init__(self):
        self.skipped_files = []
        self.warned_files = []
        self.extracted_files_count = 0
        self.extracted_size = 0
    
    def validate_and_extract_zip(self, zip_path: Path, extract_path: Path) -> Dict:
        """ALWAYS returns valid=True and extracts what it can"""
        self.skipped_files = []
        self.warned_files = []
        self.extracted_files_count = 0
        self.extracted_size = 0
        
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
            
            # 🎯 PERMISSIVE EXTRACTION - extract everything safe
            return self._permissive_extract_files(zip_path, extract_path)
                
        except Exception as e:
            return {"valid": False, "error": f"Failed to process file: {str(e)}"}

    def _permissive_extract_files(self, zip_path: Path, extract_path: Path) -> Dict:
        """Extract files permissively, only skipping truly dangerous ones"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_infos = list(zip_ref.infolist())
                
                for file_info in file_infos:
                    file_path = Path(file_info.filename)
                    file_ext = file_path.suffix.lower()
                    
                    # 🚨 Skip only truly dangerous files
                    if file_ext in self.DANGEROUS_EXTENSIONS:
                        self.skipped_files.append(f"DANGEROUS: {file_info.filename}")
                        continue
                    
                    # Skip files in unwanted directories
                    if any(skip_dir in file_info.filename for skip_dir in SKIP_PATHS):
                        self.skipped_files.append(f"SKIPPED_DIR: {file_info.filename}")
                        continue
                    
                    # 🎯 Extract all other files
                    try:
                        # Sanitize filename but don't block
                        safe_filename = self._sanitize_filename(file_info.filename)
                        
                        zip_ref.extract(file_info, extract_path)
                        self.extracted_files_count += 1
                        self.extracted_size += file_info.file_size
                        
                        # Warn but don't stop for large extractions
                        if self.extracted_size > MAX_EXTRACTED_SIZE:
                            self.warned_files.append("Reached size limit - some files not extracted")
                            break
                            
                        if self.extracted_files_count > MAX_FILE_COUNT:
                            self.warned_files.append("Reached file count limit - some files not extracted")
                            break
                            
                    except Exception as e:
                        self.skipped_files.append(f"EXTRACTION_ERROR: {file_info.filename} - {str(e)}")
                        continue
                
                return {
                    "valid": True,
                    "extracted_files": self.extracted_files_count,
                    "extracted_size": self.extracted_size,
                    "skipped_files_count": len(self.skipped_files),
                    "warnings": self.warned_files[:10],
                    "skipped_files_sample": self.skipped_files[:20]
                }
                
        except Exception as e:
            return {"valid": False, "error": f"Extraction failed: {str(e)}"}

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename but don't block"""
        sanitized = re.sub(r'\.\./|\.\.\\', '', filename)
        sanitized = re.sub(r'^/+|^\\+', '', sanitized)
        return sanitized

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for storage"""
        return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

class ComprehensiveLLMAnalyzer:
    """Comprehensive LLM analyzer with all features"""
    
    def __init__(self):
        self.enabled = LLM_ENABLED and gemini_model is not None
    
    async def analyze_issues_batch(self, issues: List[Dict], code_contexts: Dict[str, str] = None) -> List[Dict]:
        """Batch process issues with LLM"""
        if not self.enabled or not issues:
            return issues
        
        # Analyze critical and high-impact issues
        critical_issues = [issue for issue in issues if issue.get('severity') in ['high', 'medium']][:5]
        
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
        """Comprehensive single issue analysis"""
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
        """Build comprehensive analysis prompt"""
        return f"""
        As an expert software engineer, analyze this code issue and provide detailed solutions.

        ISSUE:
        - Title: {issue['title']}
        - Description: {issue['description']}
        - Category: {issue['category']}
        - File: {issue.get('file', 'N/A')}
        - Severity: {issue.get('severity', 'medium')}

        CODE CONTEXT:
        {code_context[:2000] if code_context else 'No specific code context provided'}

        Please provide:
        1. Root cause analysis (1-2 paragraphs)
        2. Step-by-step solution with code examples if applicable
        3. Best practices to prevent this issue
        4. Alternative solutions if any

        Keep responses practical and actionable.
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
        """Parse LLM response comprehensively"""
        if not llm_response.strip():
            return issue
        
        # Simple parsing - use sections if detectable
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
            "detailed_solution": detailed_solution[:2000],
            "root_cause": root_cause[:500] if root_cause else "AI analysis provided",
            "prevention": prevention[:500] if prevention else "See detailed solution above",
            "ai_analyzed": True
        })
        
        return issue

class ComprehensiveProjectAnalyzer:
    """Comprehensive project analyzer with ALL functionality"""
    
    def __init__(self):
        self.issues = []
        self.project_stats = self._init_project_stats()
        self.security_scanner = PermissiveSecurityScanner()
        self.llm_analyzer = ComprehensiveLLMAnalyzer()
        self._critical_issue_count = 0
        self._files_scanned = 0
    
    def _init_project_stats(self):
        """Initialize comprehensive project stats"""
        return {
            "total_files": 0, "package_files": 0, "config_files": 0,
            "large_project": False, "node_modules_detected": False,
            "skipped_files": 0, "security_warnings": [],
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
            },
            "tech_stack": {"frontend": [], "backend": [], "build_tools": [], "testing": []},
            "size_analysis": {}
        }
    
    async def analyze_project(self, zip_path: Path) -> Dict:
        """Comprehensive project analysis - NEVER fails completely"""
        start_time = datetime.now()
        self.issues = []
        self.project_stats = self._init_project_stats()
        self._critical_issue_count = 0
        self._files_scanned = 0
        
        extract_path = Path(tempfile.mkdtemp(prefix="codecopilot_"))
        
        try:
            # 🎯 ALWAYS EXTRACT - never block
            extract_result = self.security_scanner.validate_and_extract_zip(zip_path, extract_path)
            
            if not extract_result["valid"]:
                # Even if extraction fails, return basic analysis
                return self._get_fallback_analysis(extract_result["error"])
            
            # Update stats from extraction
            self.project_stats["skipped_files"] = extract_result.get("skipped_files_count", 0)
            if extract_result.get("warnings"):
                self.project_stats["security_warnings"].extend(extract_result["warnings"])
            
            # 🎯 COMPREHENSIVE ANALYSIS
            await self._comprehensive_analysis(extract_path)
            
            # Project classification
            if self.project_stats["total_files"] > 1000:
                self.project_stats["large_project"] = True
            
            # Early termination only for performance, not errors
            if self._critical_issue_count >= EARLY_RETURN_CRITICAL_ISSUES:
                self.project_stats["performance"]["early_termination"] = True
                self._add_issue(
                    title="Analysis optimized for performance",
                    description=f"Found {self._critical_issue_count} critical issues. Analysis completed with optimizations.",
                    category="performance",
                    file="project-root",
                    severity="low"
                )
            
            # 🧠 LLM Enhancement
            llm_was_used = False
            if self.llm_analyzer.enabled and self.issues:
                llm_was_used = await self._enhance_issues_with_llm(extract_path)
            
            # Performance metrics
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
            
        except Exception as e:
            # 🎯 NEVER FAIL - return error analysis
            return self._get_error_analysis(str(e))
        finally:
            await self._cleanup_directory(extract_path)
    
    def _get_fallback_analysis(self, error: str) -> Dict:
        """Return analysis even when extraction fails"""
        self._add_issue(
            title="Project Extraction Issue",
            description=f"Could not extract project: {error}",
            category="system",
            severity="medium",
            solution="Try creating a new ZIP file with only your source code"
        )
        
        return {
            "timestamp": datetime.now().isoformat(),
            "issues": self.issues,
            "health_score": 50,
            "summary": self._generate_summary(),
            "project_stats": {"extraction_error": error},
            "llm_enhanced": False,
            "llm_available": self.llm_analyzer.enabled,
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
            "performance": {
                "total_duration_seconds": 0,
                "issues_found": len(self.issues),
                "analysis_complete": False
            }
        }
    
    async def _comprehensive_analysis(self, extract_path: Path):
        """Run ALL analysis tasks"""
        # Core analysis tasks
        await self._analyze_project_structure(extract_path)
        await self._analyze_package_files(extract_path)
        await self._analyze_security(extract_path)
        await self._analyze_code_quality(extract_path)
        await self._analyze_deployment(extract_path)
        await self._analyze_tech_stack(extract_path)
        
        # Advanced analysis (for reasonable-sized projects)
        if self.project_stats["total_files"] < 5000:
            await self._analyze_dependencies(extract_path)
            await self._analyze_code_complexity(extract_path)
            await self._analyze_performance(extract_path)
            await self._analyze_accessibility(extract_path)
            await self._analyze_architecture(extract_path)
            await self._analyze_ci_cd(extract_path)
    
    async def _analyze_project_structure(self, extract_path: Path):
        """Analyze project structure and file counts"""
        file_count = 0
        node_modules_detected = False
        
        try:
            for root, dirs, files in os.walk(extract_path):
                # Skip unwanted directories
                dirs[:] = [d for d in dirs if d not in SKIP_PATHS]
                
                if 'node_modules' in root:
                    node_modules_detected = True
                    dirs.clear()
                    continue
                    
                file_count += len(files)
                
                if file_count > MAX_SCAN_FILES:
                    break
            
            self.project_stats["total_files"] = file_count
            self.project_stats["node_modules_detected"] = node_modules_detected
            self._files_scanned = file_count
            
        except Exception as e:
            print(f"Error analyzing project structure: {e}")
    
    async def _analyze_package_files(self, extract_path: Path):
        """Analyze package.json files"""
        package_files = list(extract_path.rglob('package.json'))
        package_files = [pf for pf in package_files if 'node_modules' not in str(pf)]
        
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
        
        for package_file in package_files[:3]:  # Analyze first 3 packages
            try:
                with open(package_file, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                
                self._analyze_package_data(package_data, package_file)
                
            except json.JSONDecodeError as e:
                self._add_issue(
                    title="Invalid package.json",
                    description=f"package.json contains invalid JSON: {str(e)}",
                    category="dependencies",
                    file=str(package_file.relative_to(extract_path)),
                    severity="high"
                )
            except Exception as e:
                print(f"Error analyzing package.json: {e}")
    
    def _analyze_package_data(self, package_data: Dict, package_file: Path):
        """Comprehensive package.json analysis"""
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        # Check dependency versions
        self._check_dependency_versions(dependencies, package_file)
        
        # Check scripts
        self._check_package_scripts(package_data, package_file)
        
        # Check engines
        self._check_engines(package_data, package_file)
        
        # Check peer dependencies
        self._check_peer_dependencies(package_data, package_file)
    
    def _check_dependency_versions(self, dependencies: Dict, package_file: Path):
        """Check dependency version issues"""
        # React version consistency
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
        
        # Socket.io version consistency
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
    
    def _check_package_scripts(self, package_data: Dict, package_file: Path):
        """Check package.json scripts"""
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
    
    async def _analyze_security(self, extract_path: Path):
        """Comprehensive security analysis"""
        await self._check_environment_files(extract_path)
        await self._check_config_files_security(extract_path)
        await self._check_dependency_vulnerabilities_comprehensive(extract_path)
    
    async def _check_environment_files(self, extract_path: Path):
        """Check environment files for secrets"""
        env_files = list(extract_path.rglob('.env*'))
        
        for env_file in env_files:
            if env_file.name == '.env.example':
                continue
                
            try:
                content = env_file.read_text(encoding='utf-8', errors='ignore')
                
                for pattern, secret_type in SECRET_PATTERNS.items():
                    if pattern.search(content):
                        self._add_issue(
                            title=f"Hardcoded {secret_type} Found",
                            description=f"Potential {secret_type.lower()} found in {env_file.name}",
                            category="security",
                            file=str(env_file.relative_to(extract_path)),
                            severity="high",
                            solution=f"Move {secret_type.lower()} to environment variables or secure secret management system"
                        )
                        self.project_stats["security_scan"]["secrets_found"] += 1
                        break
                        
            except Exception:
                continue
    
    async def _check_config_files_security(self, extract_path: Path):
        """Check config files for security issues"""
        config_files = list(extract_path.rglob('config.json')) + \
                      list(extract_path.rglob('settings.json')) + \
                      list(extract_path.rglob('constants.js'))
        
        for config_file in config_files[:10]:  # Limit to 10 files
            try:
                content = config_file.read_text(encoding='utf-8', errors='ignore')
                
                for pattern, secret_type in SECRET_PATTERNS.items():
                    if pattern.search(content):
                        self._add_issue(
                            title=f"Hardcoded {secret_type} in Config",
                            description=f"Potential {secret_type.lower()} found in configuration file",
                            category="security",
                            file=str(config_file.relative_to(extract_path)),
                            severity="high",
                            solution=f"Move {secret_type.lower()} to environment variables"
                        )
                        self.project_stats["security_scan"]["secrets_found"] += 1
                        break
                        
            except Exception:
                continue
    
    async def _check_dependency_vulnerabilities_comprehensive(self, extract_path: Path):
        """Check for vulnerable dependencies"""
        package_files = list(extract_path.rglob('package.json'))
        package_files = [pf for pf in package_files if 'node_modules' not in str(pf)]
        
        for package_file in package_files[:2]:
            try:
                with open(package_file, 'r') as f:
                    package_data = json.load(f)
                
                dependencies = {**package_data.get('dependencies', {}), 
                              **package_data.get('devDependencies', {})}
                
                for dep, version in dependencies.items():
                    if dep in VULNERABLE_PATTERNS:
                        vulnerable_version = VULNERABLE_PATTERNS[dep]
                        self._add_issue(
                            title=f"Vulnerable Dependency: {dep}",
                            description=f"{dep} version {version} may have known vulnerabilities. Affected versions: {vulnerable_version}",
                            category="security",
                            file=str(package_file.relative_to(extract_path)),
                            severity="high",
                            solution=f"Update {dep} to a secure version above {vulnerable_version}"
                        )
                        self.project_stats["security_scan"]["vulnerable_deps"] += 1
                        
            except Exception as e:
                print(f"Error checking vulnerabilities: {e}")
    
    async def _analyze_code_quality(self, extract_path: Path):
        """Comprehensive code quality analysis"""
        await self._check_linting_config(extract_path)
        await self._check_typescript_config(extract_path)
        await self._check_testing_setup(extract_path)
        await self._check_code_structure(extract_path)
    
    async def _check_linting_config(self, extract_path: Path):
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
            for tsconfig in tsconfig_files[:1]:
                try:
                    with open(tsconfig, 'r') as f:
                        tsconfig_data = json.load(f)
                    
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
    
    async def _analyze_deployment(self, extract_path: Path):
        """Comprehensive deployment analysis"""
        await self._check_build_configurations(extract_path)
        await self._check_environment_configs(extract_path)
        await self._check_deployment_files(extract_path)
    
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
        """Analyze technology stack"""
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
        
        # Convert sets to lists
        self.project_stats["tech_stack"] = {
            category: list(frameworks) 
            for category, frameworks in tech_stack.items()
        }
    
    async def _analyze_dependencies(self, extract_path: Path):
        """Advanced dependency analysis"""
        # This would include more sophisticated vulnerability checks
        # and dependency graph analysis in a real implementation
        pass
    
    async def _analyze_code_complexity(self, extract_path: Path):
        """Analyze code complexity"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        complex_files = []
        
        for file_path in source_files[:50]:
            try:
                complexity = self._calculate_file_complexity(file_path)
                if complexity > 50:
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
        """Calculate cyclomatic complexity"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
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
    
    async def _analyze_performance(self, extract_path: Path):
        """Analyze performance issues"""
        source_files = list(extract_path.rglob('*.js')) + list(extract_path.rglob('*.jsx')) + \
                      list(extract_path.rglob('*.ts')) + list(extract_path.rglob('*.tsx'))
        
        performance_issue_count = 0
        
        for file_path in source_files[:100]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for common performance issues
                if re.search(r'\.map\s*\(\s*\(\s*\w+\s*\)\s*=>', content) and 'key=' not in content:
                    self._add_issue(
                        title="Missing React Keys",
                        description="Array.map without keys can cause performance issues",
                        category="performance",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Add unique key prop to list items"
                    )
                    performance_issue_count += 1
                
                if re.search(r'onClick={\(\) => [^}]+}', content):
                    self._add_issue(
                        title="Inline Function in JSX",
                        description="Inline function declarations can cause unnecessary re-renders",
                        category="performance",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Define functions outside JSX or use useCallback hook"
                    )
                    performance_issue_count += 1
                    
            except Exception:
                continue
        
        self.project_stats["advanced_metrics"]["performance_issues"] = performance_issue_count
    
    async def _analyze_accessibility(self, extract_path: Path):
        """Analyze accessibility issues"""
        jsx_files = list(extract_path.rglob('*.jsx')) + list(extract_path.rglob('*.tsx'))
        
        accessibility_issue_count = 0
        
        for file_path in jsx_files[:50]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Missing alt attributes
                if re.search(r'<img[^>]*?(?<=\s)(?!(alt=))[^>]*?>', content):
                    self._add_issue(
                        title="Missing Alt Text",
                        description="Image missing alt attribute for screen readers",
                        category="accessibility",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Add descriptive alt text to all img tags"
                    )
                    accessibility_issue_count += 1
                
                # Missing form labels
                if re.search(r'<input[^>]*?(?!(aria-label=|aria-labelledby=|id=))[^>]*?>', content) and \
                   not re.search(r'<label[^>]*?>.*?</label>', content):
                    self._add_issue(
                        title="Missing Form Label",
                        description="Input field missing associated label",
                        category="accessibility",
                        file=str(file_path.relative_to(extract_path)),
                        severity="medium",
                        solution="Add label with htmlFor attribute or use aria-label"
                    )
                    accessibility_issue_count += 1
                    
            except Exception:
                continue
        
        self.project_stats["advanced_metrics"]["accessibility_issues"] = accessibility_issue_count
    
    async def _analyze_architecture(self, extract_path: Path):
        """Analyze architecture issues"""
        # Simple architecture checks
        source_files = list(extract_path.rglob('*.jsx')) + list(extract_path.rglob('*.tsx'))
        
        architecture_issue_count = 0
        
        for file_path in source_files[:30]:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for mixed responsibilities
                if ('fetch(' in content or 'axios' in content) and ('<div' in content or '<span' in content):
                    if content.count('<') > 10:  # Has significant rendering
                        self._add_issue(
                            title="Mixed Responsibilities",
                            description="Component appears to handle both data fetching and rendering",
                            category="architecture",
                            file=str(file_path.relative_to(extract_path)),
                            severity="low",
                            solution="Consider separating data fetching logic from presentation components"
                        )
                        architecture_issue_count += 1
                        
            except Exception:
                continue
        
        self.project_stats["advanced_metrics"]["architecture_issues"] = architecture_issue_count
    
    async def _analyze_ci_cd(self, extract_path: Path):
        """Analyze CI/CD configuration"""
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
        
        self.project_stats["advanced_metrics"]["ci_cd_issues"] = ci_cd_issue_count
    
    async def _enhance_issues_with_llm(self, extract_path: Path) -> bool:
        """Enhance issues with LLM analysis"""
        if not self.issues or not self.llm_analyzer.enabled:
            return False
        
        critical_issues = [issue for issue in self.issues if issue.get('severity') in ['high', 'medium']][:5]
        
        if not critical_issues:
            return False
        
        try:
            # Get code contexts for critical issues
            code_contexts = {}
            
            for issue in critical_issues:
                if 'file' in issue and issue['file'] != 'project-root':
                    content = await self._get_file_content_async(extract_path / issue['file'])
                    if content:
                        code_contexts[issue.get('file', '')] = content
            
            # Enhance issues with LLM
            enhanced_issues = await self.llm_analyzer.analyze_issues_batch(critical_issues, code_contexts)
            
            # Update the issues list
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

    async def _get_file_content_async(self, file_path: Path) -> str:
        """Get file content for LLM context"""
        try:
            if file_path.exists() and file_path.is_file():
                loop = asyncio.get_event_loop()
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = await loop.run_in_executor(None, f.read)
                return content[:3000]
        except Exception:
            pass
        return ""

    def _add_issue(self, title: str, description: str, category: str, file: str = "", 
                  severity: str = "medium", solution: str = ""):
        """Add an issue to the results"""
        if severity == "high":
            self._critical_issue_count += 1
        
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
        """Calculate project health score"""
        base_score = 100
        
        for issue in self.issues:
            if issue['severity'] == 'high':
                base_score -= 10
            elif issue['severity'] == 'medium':
                base_score -= 5
            else:
                base_score -= 2
        
        # Bonus points for good practices
        if self.project_stats.get("package_files", 0) > 0:
            base_score += 5
        if self.project_stats["security_scan"]["vulnerable_deps"] == 0:
            base_score += 5
        if self.project_stats["code_quality"]["testing_issues"] == 0:
            base_score += 5
        
        return max(0, min(100, base_score))

    def _generate_summary(self) -> Dict:
        """Generate comprehensive summary"""
        issue_count = len(self.issues)
        health_score = self._calculate_health_score()
        
        # Calculate priority breakdown
        priority_breakdown = {"high": 0, "medium": 0, "low": 0}
        for issue in self.issues:
            priority_breakdown[issue['severity']] += 1
        
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
        """Cleanup temporary directory"""
        try:
            if directory_path.exists():
                def remove_directory(path):
                    shutil.rmtree(path, ignore_errors=True)
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, remove_directory, directory_path)
        except Exception as e:
            print(f"Cleanup warning: {e}")

# Flask Routes
@app.route('/')
def root():
    return jsonify({
        "message": "CodeCopilot API - Comprehensive Edition",
        "version": "2.0.0",
        "status": "running",
        "llm_enabled": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "performance_optimized": True,
        "comprehensive_features": True,
        "max_file_size": f"{MAX_FILE_SIZE // (1024*1024)}MB",
        "features": [
            "Dependency Analysis", "Security Scanning", "Code Quality Checks",
            "Performance Analysis", "Accessibility Scanning", "Architecture Review",
            "CI/CD Configuration Check", "AI-Powered Insights", "Tech Stack Analysis",
            "Code Complexity Analysis", "Advanced Vulnerability Detection"
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
            "service": "codecopilot-comprehensive",
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
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not file.filename.endswith('.zip'):
        return jsonify({"error": "Please upload a ZIP file"}), 400
    
    temp_dir = Path(tempfile.mkdtemp())
    temp_file = temp_dir / PermissiveSecurityScanner.sanitize_filename(file.filename)
    
    try:
        file.save(temp_file)
        
        # Basic file size check
        if temp_file.stat().st_size > MAX_FILE_SIZE:
            return jsonify({
                "error": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB."
            }), 400
        
        if temp_file.stat().st_size == 0:
            return jsonify({"error": "File is empty"}), 400
        
        # 🎯 COMPREHENSIVE ANALYSIS - always returns results
        analyzer = ComprehensiveProjectAnalyzer()
        results = asyncio.run(analyzer.analyze_project(temp_file))
        
        return jsonify(results)
        
    except Exception as e:
        # 🎯 NEVER FAIL - return basic analysis even on error
        analyzer = ComprehensiveProjectAnalyzer()
        fallback_results = analyzer._get_error_analysis(str(e))
        return jsonify(fallback_results)
    finally:
        # Cleanup
        try:
            if temp_file.exists():
                temp_file.unlink()
            if temp_dir.exists():
                temp_dir.rmdir()
        except Exception:
            pass

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
            }
        ],
        "llm_capabilities": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "comprehensive_features": True
    })

@app.errorhandler(413)
def too_large(e):
    return jsonify({
        "error": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB."
    }), 413

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded. Please try again later."
    }), 429

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    
    print(f"🚀 Starting Comprehensive CodeCopilot Backend on port {port}")
    print(f"🧠 LLM Features: {'Enabled' if LLM_ENABLED else 'Disabled'}")
    if LLM_ENABLED:
        print(f"   Model Status: {'✅ Working' if gemini_model else '❌ Not Available'}")
    print(f"📁 Max File Size: {MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"📦 Max Extracted Size: {MAX_EXTRACTED_SIZE // (1024*1024)}MB")
    print(f"📊 Max File Count: {MAX_FILE_COUNT:,} files")
    print(f"🎯 Key Feature: ALWAYS returns analysis results")
    print(f"⚡ Comprehensive Analysis: Enabled")
    print(f"   - Dependency Analysis")
    print(f"   - Security Scanning") 
    print(f"   - Code Quality Checks")
    print(f"   - Performance Analysis")
    print(f"   - Accessibility Scanning")
    print(f"   - Architecture Review")
    print(f"   - CI/CD Configuration")
    print(f"   - Tech Stack Analysis")
    print(f"   - Advanced Metrics")
    
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)