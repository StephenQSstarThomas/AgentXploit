"""
Analysis Context Manager - provides agents with project structure history,
discovery context, and collaborative todo management.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from ..core.analysis_context import AnalysisContext


class AnalysisContextManager:
    """Manages analysis history and project understanding for agent decision-making"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.project_structure = {}
        self.discovery_timeline = []
        self.analysis_todos = []
        self.completed_analysis = []
        self.security_findings = []
        self.architectural_insights = {}
        
    def update_project_structure(self, path: str, structure_data: Dict[str, Any]):
        """Update understanding of project structure"""
        self.project_structure[path] = {
            "discovered_at": datetime.now().isoformat(),
            "structure": structure_data,
            "files": structure_data.get("files", []),
            "directories": structure_data.get("directories", [])
        }
        
        # Add to timeline
        self.discovery_timeline.append({
            "timestamp": datetime.now().isoformat(),
            "type": "structure_discovery",
            "path": path,
            "files_found": len(structure_data.get("files", [])),
            "dirs_found": len(structure_data.get("directories", []))
        })
    
    def add_analysis_result(self, file_path: str, analysis_data: Dict[str, Any]):
        """Record analysis results for future reference"""
        analysis_record = {
            "file_path": file_path,
            "analyzed_at": datetime.now().isoformat(),
            "analysis_data": analysis_data,
            "security_risk": analysis_data.get("security_risk", "unknown"),
            "key_findings": analysis_data.get("key_findings", [])
        }
        
        self.completed_analysis.append(analysis_record)
        
        # Extract security findings
        if analysis_data.get("security_risk") in ["high", "medium"]:
            self.security_findings.append({
                "file": file_path,
                "risk_level": analysis_data["security_risk"],
                "findings": analysis_data.get("key_findings", []),
                "found_at": datetime.now().isoformat()
            })
        
        # Add to timeline
        self.discovery_timeline.append({
            "timestamp": datetime.now().isoformat(),
            "type": "file_analysis",
            "file": file_path,
            "risk_level": analysis_data.get("security_risk", "unknown")
        })
    
    def add_todo(self, description: str, priority: str = "medium", context: str = ""):
        """Add analysis todo (called by agents)"""
        todo = {
            "id": f"todo_{len(self.analysis_todos)}",
            "description": description,
            "priority": priority,
            "context": context,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "created_by": "agent"
        }
        self.analysis_todos.append(todo)
        return todo["id"]
    
    def update_todo_status(self, todo_id: str, status: str, notes: str = ""):
        """Update todo status"""
        for todo in self.analysis_todos:
            if todo["id"] == todo_id:
                todo["status"] = status
                todo["updated_at"] = datetime.now().isoformat()
                if notes:
                    todo["notes"] = notes
                if status == "completed":
                    todo["completed_at"] = datetime.now().isoformat()
                return True
        return False
    
    def get_project_overview(self) -> Dict[str, Any]:
        """Get comprehensive project overview for agent context"""
        
        # Analyze project structure patterns
        all_files = []
        all_dirs = []
        for structure in self.project_structure.values():
            all_files.extend(structure.get("files", []))
            all_dirs.extend(structure.get("directories", []))
        
        # Categorize files by type
        file_types = {}
        entry_points = []
        config_files = []
        security_files = []
        
        for file in all_files:
            ext = Path(file).suffix
            file_types[ext] = file_types.get(ext, 0) + 1
            
            file_lower = file.lower()
            if any(name in file_lower for name in ["main", "app", "cli", "run", "start"]):
                entry_points.append(file)
            if any(name in file_lower for name in ["config", "settings", "env"]):
                config_files.append(file)
            if any(name in file_lower for name in ["auth", "security", "login", "user"]):
                security_files.append(file)
        
        # Determine project type/framework
        project_type = "unknown"
        if any(".py" in f for f in all_files):
            project_type = "python"
            if "pyproject.toml" in all_files or "setup.py" in all_files:
                project_type = "python_package"
        
        return {
            "repo_path": str(self.repo_path),
            "project_type": project_type,
            "total_files": len(all_files),
            "total_directories": len(all_dirs),
            "file_types": file_types,
            "entry_points": entry_points,
            "config_files": config_files,
            "security_relevant_files": security_files,
            "analysis_progress": {
                "files_analyzed": len(self.completed_analysis),
                "security_findings": len(self.security_findings),
                "pending_todos": len([t for t in self.analysis_todos if t["status"] == "pending"]),
                "completed_todos": len([t for t in self.analysis_todos if t["status"] == "completed"])
            },
            "last_updated": datetime.now().isoformat()
        }
    
    def get_analysis_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent analysis history for context"""
        return sorted(
            self.discovery_timeline, 
            key=lambda x: x["timestamp"], 
            reverse=True
        )[:limit]
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security findings summary"""
        high_risk = [f for f in self.security_findings if f["risk_level"] == "high"]
        medium_risk = [f for f in self.security_findings if f["risk_level"] == "medium"]
        
        return {
            "total_findings": len(self.security_findings),
            "high_risk_count": len(high_risk),
            "medium_risk_count": len(medium_risk),
            "high_risk_files": [f["file"] for f in high_risk],
            "recent_findings": self.security_findings[-5:] if self.security_findings else [],
            "summary_generated_at": datetime.now().isoformat()
        }
    
    def get_current_todos(self) -> List[Dict[str, Any]]:
        """Get current analysis todos"""
        return [todo for todo in self.analysis_todos if todo["status"] in ["pending", "in_progress"]]
    
    def suggest_next_priorities(self) -> List[str]:
        """Suggest what should be prioritized next based on discoveries"""
        suggestions = []
        
        overview = self.get_project_overview()
        
        # Suggest entry points if not analyzed
        analyzed_files = [a["file_path"] for a in self.completed_analysis]
        unanalyzed_entry_points = [f for f in overview["entry_points"] if f not in analyzed_files]
        if unanalyzed_entry_points:
            suggestions.append(f"Analyze entry points: {', '.join(unanalyzed_entry_points[:3])}")
        
        # Suggest config files if not analyzed
        unanalyzed_config = [f for f in overview["config_files"] if f not in analyzed_files]
        if unanalyzed_config:
            suggestions.append(f"Review configuration files: {', '.join(unanalyzed_config[:3])}")
        
        # Suggest security files if not analyzed
        unanalyzed_security = [f for f in overview["security_relevant_files"] if f not in analyzed_files]
        if unanalyzed_security:
            suggestions.append(f"Security analysis: {', '.join(unanalyzed_security[:3])}")
        
        # Suggest follow-up on high-risk findings
        if len([f for f in self.security_findings if f["risk_level"] == "high"]) > 0:
            suggestions.append("Investigate high-risk security findings further")
        
        return suggestions[:5]
    
    def export_context(self) -> Dict[str, Any]:
        """Export full context for persistence or analysis"""
        return {
            "repo_path": str(self.repo_path),
            "project_structure": self.project_structure,
            "discovery_timeline": self.discovery_timeline,
            "analysis_todos": self.analysis_todos,
            "completed_analysis": self.completed_analysis,
            "security_findings": self.security_findings,
            "architectural_insights": self.architectural_insights,
            "exported_at": datetime.now().isoformat()
        }