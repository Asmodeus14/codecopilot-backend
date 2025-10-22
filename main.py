import os
import json
import zipfile
import tempfile
import shutil
import re
import asyncio
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from dotenv import load_dotenv

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

# 🚀 SECURE FILE SIZE LIMITS WITH ZIP BOMB PROTECTION
MAX_FILE_SIZE = 400 * 1024 * 1024  # 400MB max file size
MAX_EXTRACTED_SIZE = 800 * 1024 * 1024  # 800MB for extracted content
MAX_FILE_COUNT = 50000  # 50,000 files
MAX_COMPRESSION_RATIO = 50  # Maximum compression ratio (50:1)
MAX_DEPTH = 20  # Maximum directory depth to prevent deep nesting attacks

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
    "https://codecopilot0.vercel.app"
])

# Initialize Gemini if available with better error handling
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
LLM_ENABLED = False
gemini_model = None

if GEMINI_API_KEY and GEMINI_AVAILABLE:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        
        # Try different model names - they vary by region and API version
        available_models = []
        
        # Common model names to try
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
                available_models.append(model_name)
                gemini_model = model
                print(f"✅ Model {model_name} is available")
                break  # Use the first available model
            except Exception as model_error:
                print(f"❌ Model {model_name} not available: {model_error}")
                continue
        
        if gemini_model:
            LLM_ENABLED = True
            print(f"🎯 Using Gemini model: {available_models[0]}")
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

# Security Scanner (keep your existing implementation)
class SecurityScanner:
    """Enhanced security scanner with comprehensive zip bomb protection"""
    
    # 🚨 Files that should be completely skipped (not extracted)
    SKIP_EXTENSIONS = {
        '.bat', '.cmd', '.ps1', '.sh',  # Executable scripts
        '.scr', '.com', '.pif', '.msi', # Windows executable types
        '.jar', '.war', '.apk',         # Archives that can execute code
    }
    
    # 📁 Allow these in node_modules (common for legitimate packages)
    ALLOW_IN_NODE_MODULES = {
        '.exe', '.dll', '.so', '.dylib',  # Binaries allowed in node_modules
    }
    
    def __init__(self):
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
    
    def validate_and_extract_zip(self, zip_path: Path, extract_path: Path) -> Dict:
        """Extract ZIP file with comprehensive security checks"""
        self.skipped_files = []
        self.warned_files = []
        self.detected_threats = []
        
        try:
            # Basic ZIP validation
            if not self._is_valid_zip(zip_path):
                return {"valid": False, "error": "This doesn't appear to be a valid ZIP file. Please make sure you're uploading a properly compressed project folder."}
            
            # Comprehensive zip bomb detection
            bomb_check = self._detect_zip_bomb(zip_path)
            if not bomb_check["safe"]:
                return self._get_zip_bomb_error_message(bomb_check)
            
            extract_path.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Extract files selectively with progress monitoring
                extracted_size = 0
                extracted_files = 0
                
                for file_info in zip_ref.infolist():
                    # Check extraction progress to prevent resource exhaustion
                    if extracted_files > MAX_FILE_COUNT:
                        return {"valid": False, "error": "This project contains too many files for analysis. Try removing the node_modules folder or splitting your project into smaller parts."}
                    
                    if extracted_size > MAX_EXTRACTED_SIZE:
                        return {"valid": False, "error": "This project is too large to analyze safely. The maximum extracted size is 800MB. Try removing large files like videos, images, or node_modules."}
                    
                    if self._should_skip_file(file_info.filename):
                        self.skipped_files.append(file_info.filename)
                        continue
                    
                    # Safe to extract
                    try:
                        zip_ref.extract(file_info, extract_path)
                        extracted_size += file_info.file_size
                        extracted_files += 1
                    except Exception as e:
                        print(f"Warning: Failed to extract {file_info.filename}: {e}")
                        continue
            
            return {
                "valid": True,
                "skipped_files": self.skipped_files,
                "total_skipped": len(self.skipped_files),
                "extracted_files": extracted_files,
                "extracted_size": extracted_size,
                "threats_detected": self.detected_threats
            }
            
        except zipfile.BadZipFile:
            return {"valid": False, "error": "This file appears to be corrupted or not a valid ZIP file. Please try creating a new ZIP file of your project."}
        except Exception as e:
            return {"valid": False, "error": f"Failed to process your project: {str(e)}"}

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

    def _detect_zip_bomb(self, zip_path: Path) -> Dict:
        """Comprehensive zip bomb detection"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                total_files = 0
                total_uncompressed_size = 0
                max_compression_ratio = 0
                max_depth = 0
                
                for file_info in zip_ref.infolist():
                    total_files += 1
                    
                    # Check file count
                    if total_files > MAX_FILE_COUNT:
                        return {
                            "safe": False, 
                            "reason": f"Too many files ({total_files} > {MAX_FILE_COUNT})"
                        }
                    
                    # Check individual file compression ratio
                    if file_info.compress_size > 0:
                        ratio = file_info.file_size / file_info.compress_size
                        max_compression_ratio = max(max_compression_ratio, ratio)
                        
                        if ratio > MAX_COMPRESSION_RATIO:
                            return {
                                "safe": False,
                                "reason": f"Suspicious compression ratio ({ratio:.1f}:1) in {file_info.filename}"
                            }
                    
                    # Check for path traversal and directory depth
                    if '..' in file_info.filename or file_info.filename.startswith('/'):
                        return {"safe": False, "reason": "Path traversal attempt detected"}
                    
                    # Calculate directory depth
                    depth = file_info.filename.count('/') + file_info.filename.count('\\')
                    max_depth = max(max_depth, depth)
                    
                    if depth > MAX_DEPTH:
                        return {
                            "safe": False,
                            "reason": f"Excessive directory depth ({depth} levels)"
                        }
                    
                    # Check for recursive archive attacks
                    file_ext = Path(file_info.filename).suffix.lower()
                    if file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                        self.detected_threats.append(f"Nested archive: {file_info.filename}")
                    
                    # Accumulate total size
                    total_uncompressed_size += file_info.file_size
                    
                    # Check total uncompressed size
                    if total_uncompressed_size > MAX_EXTRACTED_SIZE:
                        return {
                            "safe": False,
                            "reason": f"Total uncompressed size too large ({total_uncompressed_size // (1024*1024)}MB)"
                        }
                
                # Check for quasi-zip-bomb
                file_stat = zip_path.stat()
                if file_stat.st_size > 0:
                    overall_ratio = total_uncompressed_size / file_stat.st_size
                    if overall_ratio > MAX_COMPRESSION_RATIO:
                        return {
                            "safe": False,
                            "reason": f"Suspicious overall compression ratio ({overall_ratio:.1f}:1)"
                        }
                
                return {"safe": True, "reason": "No threats detected"}
                
        except Exception as e:
            return {"safe": False, "reason": f"Security scan failed: {str(e)}"}

    def _is_valid_zip(self, file_path: Path) -> bool:
        """Basic ZIP file validation"""
        if file_path.suffix.lower() != '.zip':
            return False
        
        if not file_path.exists():
            return False
        
        if file_path.stat().st_size == 0:
            return False
        
        return True

    def _should_skip_file(self, filename: str) -> bool:
        """Check if a file should be completely skipped"""
        file_ext = Path(filename).suffix.lower()
        filename_lower = filename.lower()
        
        # Skip truly dangerous file types
        if file_ext in self.SKIP_EXTENSIONS:
            return True
        
        # Skip nested archives
        if file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
            return True
        
        # Allow binaries in node_modules
        if file_ext in self.ALLOW_IN_NODE_MODULES and 'node_modules/' in filename_lower:
            return False
        
        # Skip binaries outside node_modules
        if file_ext in self.ALLOW_IN_NODE_MODULES:
            return True
        
        return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

class LLMAnalyzer:
    """LLM-powered code analysis - Optional with fallback"""
    
    def __init__(self):
        self.enabled = LLM_ENABLED and gemini_model is not None
    
    async def analyze_issue_with_llm(self, issue: Dict, code_context: str = "") -> Dict:
        """Use Gemini to provide intelligent analysis and solutions"""
        if not self.enabled:
            return issue
        
        try:
            prompt = self._build_analysis_prompt(issue, code_context)
            response = await self._get_llm_response(prompt)
            
            if response:
                enhanced_issue = self._parse_llm_response(issue, response)
                return enhanced_issue
            else:
                # If LLM fails, return the original issue with a note
                issue["llm_fallback"] = "AI analysis temporarily unavailable"
                return issue
                
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            # Don't break the analysis if LLM fails
            issue["llm_fallback"] = "AI analysis failed - showing basic analysis"
            return issue
    
    def _build_analysis_prompt(self, issue: Dict, code_context: str) -> str:
        """Build prompt for LLM analysis"""
        return f"""
        As an expert web developer, analyze this code issue and provide detailed solutions.

        ISSUE:
        - Title: {issue['title']}
        - Description: {issue['description']}
        - Category: {issue['category']}
        - File: {issue.get('file', 'N/A')}

        Please provide:
        1. Root cause explanation
        2. Step-by-step solution
        3. Prevention tips

        Keep responses concise and actionable. Focus on practical solutions.
        """
    
    async def _get_llm_response(self, prompt: str) -> str:
        """Get response from Gemini API with error handling"""
        if not self.enabled or not gemini_model:
            return ""
        
        try:
            response = gemini_model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"Gemini API error: {e}")
            return ""
    
    def _parse_llm_response(self, issue: Dict, llm_response: str) -> Dict:
        """Parse LLM response and enhance the issue"""
        if not llm_response.strip():
            issue["llm_enhanced"] = False
            return issue
        
        # Simple parsing - just use the response as detailed solution
        issue.update({
            "llm_enhanced": True,
            "detailed_solution": llm_response.strip(),
            "root_cause": "Analyzed by AI",
            "prevention": "See detailed solution above"
        })
        
        return issue

class ProjectAnalyzer:
    def __init__(self):
        self.issues = []
        self.project_stats = {
            "total_files": 0,
            "package_files": 0,
            "config_files": 0,
            "large_project": False,
            "node_modules_detected": False,
            "skipped_files": 0,
            "security_warnings": [],
            "threats_detected": []
        }
        self.security_scanner = SecurityScanner()
        self.llm_analyzer = LLMAnalyzer()
    
    async def analyze_project(self, zip_path: Path) -> Dict:
        """Main analysis entry point with comprehensive security"""
        self.issues = []
        self.project_stats = {
            "total_files": 0, 
            "package_files": 0, 
            "config_files": 0, 
            "large_project": False,
            "node_modules_detected": False,
            "skipped_files": 0,
            "security_warnings": [],
            "threats_detected": []
        }
        
        extract_path = Path(tempfile.mkdtemp(prefix="codecopilot_"))
        try:
            # Extract with comprehensive security scanning
            extract_result = self.security_scanner.validate_and_extract_zip(zip_path, extract_path)
            
            if not extract_result["valid"]:
                # Add rejection reason to the error response
                if "rejection_reason" in extract_result:
                    raise ValueError(json.dumps(extract_result))
                else:
                    raise ValueError(extract_result["error"])
            
            # Record security information
            self.project_stats["skipped_files"] = extract_result["total_skipped"]
            if extract_result["skipped_files"]:
                self.project_stats["security_warnings"].append({
                    "type": "skipped_files",
                    "message": f"Skipped {extract_result['total_skipped']} potentially unsafe files",
                    "files": extract_result["skipped_files"][:10]
                })
            
            # Analyze the safely extracted project
            await self._analyze_extracted_project(extract_path)
            
            # Check if this is a large project
            if self.project_stats["total_files"] > 1000:
                self.project_stats["large_project"] = True
            
            # Enhance issues with LLM if available
            if self.llm_analyzer.enabled:
                await self._enhance_issues_with_llm(extract_path)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "issues": self.issues,
                "health_score": self._calculate_health_score(),
                "summary": self._generate_summary(),
                "project_stats": self.project_stats,
                "llm_enhanced": self.llm_analyzer.enabled,
                "llm_available": self.llm_analyzer.enabled
            }
        finally:
            await self._cleanup_directory(extract_path)
    
    async def _analyze_extracted_project(self, extract_path: Path):
        """Analyze the extracted project structure and files"""
        # Count files and detect project type
        await self._count_files(extract_path)
        
        # Find and analyze package files
        await self._find_and_analyze_package_files(extract_path)
        
        # Check project structure
        await self._check_project_structure(extract_path)
        
        # Check configuration files
        await self._check_configuration_files(extract_path)
    
    async def _count_files(self, extract_path: Path):
        """Count files and detect project characteristics"""
        for root, dirs, files in os.walk(extract_path):
            # Skip node_modules in file counting but mark its presence
            if 'node_modules' in root:
                self.project_stats["node_modules_detected"] = True
                continue
                
            self.project_stats["total_files"] += len(files)
    
    async def _find_and_analyze_package_files(self, extract_path: Path):
        """Find and analyze package.json files"""
        package_json_files = list(extract_path.rglob('package.json'))
        
        for package_file in package_json_files:
            # Skip node_modules packages
            if 'node_modules' in str(package_file):
                continue
                
            self.project_stats["package_files"] += 1
            await self._analyze_package_json(package_file)
    
    async def _analyze_package_json(self, package_file: Path):
        """Analyze a package.json file for issues"""
        try:
            with open(package_file, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
            
            # Check for socket.io version mismatches
            await self._check_socket_versions(package_data, package_file)
            
            # Check dependencies
            await self._check_dependencies(package_data, package_file)
            
            # Check peer dependencies
            await self._check_peer_dependencies(package_data, package_file)
            
            # Check scripts
            await self._check_scripts(package_data, package_file)
            
            # Check engines
            await self._check_engines(package_data, package_file)
            
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
    
    async def _check_socket_versions(self, package_data: Dict, package_file: Path):
        """Check for socket.io client/server version mismatches"""
        dependencies = package_data.get('dependencies', {})
        dev_dependencies = package_data.get('devDependencies', {})
        all_deps = {**dependencies, **dev_dependencies}
        
        socket_io_client = None
        socket_io_server = None
        
        for dep, version in all_deps.items():
            if dep == 'socket.io-client':
                socket_io_client = version
            elif dep == 'socket.io':
                socket_io_server = version
        
        if socket_io_client and socket_io_server:
            # Extract version numbers (remove ^, ~, etc.)
            client_ver = re.sub(r'[\^~>=<]', '', socket_io_client)
            server_ver = re.sub(r'[\^~>=<]', '', socket_io_server)
            
            if client_ver != server_ver:
                self._add_issue(
                    title="Socket.io version mismatch",
                    description=f"Socket.io client version ({socket_io_client}) doesn't match server version ({socket_io_server}). This can cause connection issues.",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="medium",
                    solution="Update both socket.io and socket.io-client to the same version."
                )
    
    async def _check_dependencies(self, package_data: Dict, package_file: Path):
        """Check for common dependency issues"""
        dependencies = package_data.get('dependencies', {})
        
        # Check for React version mismatches
        react_version = dependencies.get('react')
        react_dom_version = dependencies.get('react-dom')
        
        if react_version and react_dom_version:
            react_ver_clean = re.sub(r'[\^~>=<]', '', react_version)
            react_dom_ver_clean = re.sub(r'[\^~>=<]', '', react_dom_version)
            
            if react_ver_clean != react_dom_ver_clean:
                self._add_issue(
                    title="React version mismatch",
                    description=f"React version ({react_version}) doesn't match ReactDOM version ({react_dom_version}).",
                    category="dependencies",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="medium",
                    solution="Update React and ReactDOM to the same version to ensure compatibility."
                )
    
    async def _check_peer_dependencies(self, package_data: Dict, package_file: Path):
        """Check for missing peer dependencies"""
        peer_dependencies = package_data.get('peerDependencies', {})
        dependencies = package_data.get('dependencies', {})
        dev_dependencies = package_data.get('devDependencies', {})
        all_deps = {**dependencies, **dev_dependencies}
        
        missing_peers = []
        for peer_dep, version in peer_dependencies.items():
            if peer_dep not in all_deps:
                missing_peers.append(f"{peer_dep}@{version}")
        
        if missing_peers:
            self._add_issue(
                title="Missing peer dependencies",
                description=f"The following peer dependencies are declared but not installed: {', '.join(missing_peers)}",
                category="dependencies",
                file=str(package_file.relative_to(package_file.parent.parent)),
                severity="low",
                solution="Install the missing peer dependencies or remove them from peerDependencies."
            )
    
    async def _check_scripts(self, package_data: Dict, package_file: Path):
        """Check package.json scripts section"""
        scripts = package_data.get('scripts', {})
        
        if not scripts.get('start') and not scripts.get('dev'):
            self._add_issue(
                title="Missing start script",
                description="No 'start' or 'dev' script found in package.json. This might make it difficult to run the project.",
                category="configuration",
                file=str(package_file.relative_to(package_file.parent.parent)),
                severity="low",
                solution="Add a 'start' or 'dev' script to package.json for easier project execution."
            )
    
    async def _check_engines(self, package_data: Dict, package_file: Path):
        """Check Node.js engine requirements"""
        engines = package_data.get('engines', {})
        node_version = engines.get('node')
        
        if node_version:
            # Check if Node.js version is very old
            if any(old_ver in node_version for old_ver in ['0.', '4.', '6.', '8.']):
                self._add_issue(
                    title="Outdated Node.js version requirement",
                    description=f"The project requires Node.js {node_version}, which is outdated and may have security vulnerabilities.",
                    category="configuration",
                    file=str(package_file.relative_to(package_file.parent.parent)),
                    severity="medium",
                    solution="Update the engines requirement to a more recent Node.js version (e.g., ^14.0.0, ^16.0.0, or ^18.0.0)."
                )
    
    async def _check_project_structure(self, extract_path: Path):
        """Check overall project structure"""
        # Check for common missing directories
        expected_dirs = ['src', 'public', 'components', 'pages']
        missing_dirs = []
        
        for expected_dir in expected_dirs:
            if not (extract_path / expected_dir).exists():
                missing_dirs.append(expected_dir)
        
        if missing_dirs and len(missing_dirs) > 2:  # Only warn if multiple expected dirs are missing
            self._add_issue(
                title="Unconventional project structure",
                description=f"Expected directories not found: {', '.join(missing_dirs)}. This might indicate an unconventional project structure.",
                category="structure",
                file="project-root",
                severity="low"
            )
    
    async def _check_configuration_files(self, extract_path: Path):
        """Check for configuration files"""
        config_files = [
            '.eslintrc', '.eslintrc.js', '.eslintrc.json',
            '.prettierrc', '.prettierrc.js', '.prettierrc.json',
            'tsconfig.json', 'jsconfig.json',
            'webpack.config.js', 'vite.config.js', 'next.config.js'
        ]
        
        found_configs = []
        for config_file in config_files:
            if list(extract_path.rglob(config_file)):
                found_configs.append(config_file)
        
        self.project_stats["config_files"] = len(found_configs)
    
    async def _enhance_issues_with_llm(self, extract_path: Path):
        """Use LLM to enhance issue analysis"""
        enhanced_issues = []
        for issue in self.issues:
            # Get relevant code context if available
            code_context = ""
            if 'file' in issue and issue['file'] != 'project-root':
                file_path = extract_path / issue['file']
                if file_path.exists() and file_path.is_file():
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            code_context = f.read()[:2000]  # Limit context size
                    except:
                        pass
            
            enhanced_issue = await self.llm_analyzer.analyze_issue_with_llm(issue, code_context)
            enhanced_issues.append(enhanced_issue)
        
        self.issues = enhanced_issues

    def _add_issue(self, title: str, description: str, category: str, file: str = "", 
                  severity: str = "medium", solution: str = ""):
        """Add an issue to the analysis results"""
        # Map severity to priority
        severity_to_priority = {
            "high": 1,
            "medium": 2, 
            "low": 3
        }
        
        self.issues.append({
            "title": title,
            "description": description,
            "category": category,
            "file": file,
            "severity": severity,
            "priority": severity_to_priority.get(severity, 2),  # Add priority field
            "solution": solution,
            "fix": solution,  # Add fix as alias for solution
            "timestamp": datetime.now().isoformat()
        })
    
    def _calculate_health_score(self) -> int:
        """Calculate project health score (0-100)"""
        base_score = 100
        
        # Deduct points based on issues
        for issue in self.issues:
            if issue['severity'] == 'high':
                base_score -= 10
            elif issue['severity'] == 'medium':
                base_score -= 5
            else:
                base_score -= 2
        
        # Bonus for good structure
        if self.project_stats["config_files"] > 2:
            base_score += 5
        
        return max(0, min(100, base_score))
    
    def _generate_summary(self) -> Dict:
        """Generate project summary with priority breakdown"""
        issue_count = len(self.issues)
        health_score = self._calculate_health_score()
        
        # Calculate priority breakdown
        priority_breakdown = {1: 0, 2: 0, 3: 0}
        for issue in self.issues:
            if issue['severity'] == 'high':
                priority_breakdown[1] += 1
            elif issue['severity'] == 'medium':
                priority_breakdown[2] += 1
            elif issue['severity'] == 'low':
                priority_breakdown[3] += 1
        
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
            "analysis_complete": True,
            "priority_breakdown": priority_breakdown
        }
    
    async def _cleanup_directory(self, directory_path: Path):
        """Clean up temporary directory"""
        try:
            if directory_path.exists():
                # Use shutil.rmtree for recursive directory removal
                def remove_directory(path):
                    shutil.rmtree(path, ignore_errors=True)
                
                # Run in thread to avoid blocking
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, remove_directory, directory_path)
                print(f"✅ Cleaned up temporary directory: {directory_path}")
        except Exception as e:
            print(f"⚠️ Warning: Failed to cleanup directory {directory_path}: {e}")

# Flask Routes
@app.route('/')
def root():
    return jsonify({
        "message": "CodeCopilot API",
        "version": "1.0.0",
        "status": "running",
        "llm_enabled": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
        "security": {
            "max_file_size": f"{MAX_FILE_SIZE // (1024*1024)}MB",
            "max_extracted_size": f"{MAX_EXTRACTED_SIZE // (1024*1024)}MB", 
            "max_file_count": MAX_FILE_COUNT,
            "max_compression_ratio": f"{MAX_COMPRESSION_RATIO}:1",
            "zip_bomb_protection": "Enabled"
        },
        "endpoints": {
            "health": "/api/health",
            "analyze": "/api/analyze (POST)",
            "rules": "/api/rules"
        }
    })

@app.route('/api/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "codecopilot-backend",
        "llm_available": LLM_ENABLED,
        "llm_model_working": gemini_model is not None,
        "security": {
            "max_file_size_mb": MAX_FILE_SIZE // (1024*1024),
            "max_extracted_size_mb": MAX_EXTRACTED_SIZE // (1024*1024),
            "max_file_count": MAX_FILE_COUNT,
            "max_compression_ratio": MAX_COMPRESSION_RATIO,
            "max_directory_depth": MAX_DEPTH
        }
    })

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
        
        # Analyze project
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
                "id": "outdated_node_version",
                "name": "Outdated Node.js Version",
                "description": "Checks for outdated Node.js engine requirements",
                "priority": 1
            }
        ],
        "llm_capabilities": LLM_ENABLED,
        "llm_model_available": gemini_model is not None,
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
    
    print(f"🚀 Starting CodeCopilot Backend on port {port}")
    print(f"🧠 LLM Features: {'Enabled' if LLM_ENABLED else 'Disabled'}")
    if LLM_ENABLED:
        print(f"   Model Status: {'✅ Working' if gemini_model else '❌ Not Available'}")
    print(f"📁 Max File Size: {MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"📦 Max Extracted Size: {MAX_EXTRACTED_SIZE // (1024*1024)}MB") 
    print(f"📊 Max File Count: {MAX_FILE_COUNT:,} files")
    print(f"🛡️  Zip Bomb Protection: Enabled")
    print(f"   - Max Compression Ratio: {MAX_COMPRESSION_RATIO}:1")
    print(f"   - Max Directory Depth: {MAX_DEPTH} levels")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        threaded=True
    )