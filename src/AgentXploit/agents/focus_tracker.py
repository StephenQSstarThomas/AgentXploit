"""
Focus Tracking System for Deep Vulnerability Analysis
Maintains analysis focus and prevents shallow exploration
"""

from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from pathlib import Path
import json


class AnalysisFocus:
    """Represents a specific analysis focus or line of investigation"""
    
    def __init__(self, focus_type: str, target: str, reason: str, priority: int = 50):
        self.focus_type = focus_type  # 'vulnerability', 'dependency', 'data_flow', 'config_chain'
        self.target = target  # Main file/directory being investigated
        self.reason = reason  # Why this became a focus
        self.priority = priority  # 1-100, higher is more urgent
        self.created_at = datetime.now()
        self.last_updated = datetime.now()
        
        # Track investigation progress
        self.related_files: Set[str] = set()
        self.key_findings: List[Dict] = []
        self.investigation_depth = 0
        self.leads_to_follow: List[str] = []
        self.status = "active"  # active, completed, abandoned
    
    def add_related_file(self, file_path: str, relationship: str = "related"):
        """Add a file that's related to this focus"""
        self.related_files.add(file_path)
        self.last_updated = datetime.now()
    
    def add_finding(self, finding: Dict):
        """Add a key finding to this focus"""
        finding['timestamp'] = datetime.now().isoformat()
        self.key_findings.append(finding)
        self.last_updated = datetime.now()
        
        # Auto-promote priority based on findings severity
        if finding.get('risk_level') == 'high':
            self.priority = min(95, self.priority + 20)
        elif finding.get('risk_level') == 'medium':
            self.priority = min(90, self.priority + 10)
    
    def add_lead(self, lead_path: str, reason: str):
        """Add a new lead to follow up on"""
        self.leads_to_follow.append({
            'path': lead_path,
            'reason': reason,
            'added_at': datetime.now().isoformat()
        })
        self.last_updated = datetime.now()
    
    def get_age_minutes(self) -> float:
        """Get age of this focus in minutes"""
        return (datetime.now() - self.created_at).total_seconds() / 60
    
    def is_stale(self, threshold_minutes: int = 30) -> bool:
        """Check if this focus has been stale for too long"""
        return (datetime.now() - self.last_updated).total_seconds() / 60 > threshold_minutes
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'focus_type': self.focus_type,
            'target': self.target,
            'reason': self.reason,
            'priority': self.priority,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'related_files': list(self.related_files),
            'key_findings': self.key_findings,
            'investigation_depth': self.investigation_depth,
            'leads_to_follow': self.leads_to_follow,
            'status': self.status
        }


class FocusTracker:
    """Manages analysis focuses and drives deep investigation"""
    
    def __init__(self):
        self.active_focuses: Dict[str, AnalysisFocus] = {}
        self.focus_history: List[AnalysisFocus] = []
        self.max_concurrent_focuses = 3
        self.focus_counter = 0
    
    def create_focus(self, focus_type: str, target: str, reason: str, 
                    findings: List[Dict] = None) -> str:
        """Create a new analysis focus"""
        self.focus_counter += 1
        focus_id = f"{focus_type}_{self.focus_counter}"
        
        # Calculate initial priority based on type and findings
        base_priorities = {
            'vulnerability': 80,
            'dependency': 70,
            'data_flow': 75,
            'config_chain': 60,
            'injection_point': 90
        }
        
        priority = base_priorities.get(focus_type, 50)
        if findings:
            # Boost priority based on findings
            high_risk_count = sum(1 for f in findings if f.get('risk_level') == 'high')
            priority += high_risk_count * 15
        
        focus = AnalysisFocus(focus_type, target, reason, min(99, priority))
        
        if findings:
            for finding in findings:
                focus.add_finding(finding)
        
        self.active_focuses[focus_id] = focus
        self._manage_focus_capacity()
        
        print(f"  [FOCUS_CREATED] {focus_type.upper()}: {target} (priority: {priority}) - {reason}")
        return focus_id
    
    def get_primary_focus(self) -> Optional[AnalysisFocus]:
        """Get the highest priority active focus"""
        if not self.active_focuses:
            return None
        
        # Sort by priority (descending) then by recency
        sorted_focuses = sorted(
            self.active_focuses.values(),
            key=lambda f: (f.priority, f.last_updated),
            reverse=True
        )
        return sorted_focuses[0]
    
    def update_focus(self, focus_id: str, finding: Dict = None, 
                    related_file: str = None, lead: Dict = None) -> bool:
        """Update an existing focus with new information"""
        if focus_id not in self.active_focuses:
            return False
        
        focus = self.active_focuses[focus_id]
        
        if finding:
            focus.add_finding(finding)
            print(f"  [FOCUS_UPDATED] Added finding to {focus.target}: {finding.get('description', 'New finding')}")
        
        if related_file:
            focus.add_related_file(related_file)
        
        if lead:
            focus.add_lead(lead['path'], lead['reason'])
            print(f"  [LEAD_ADDED] New lead for {focus.target}: {lead['path']} - {lead['reason']}")
        
        focus.investigation_depth += 1
        return True
    
    def get_next_investigation_targets(self, limit: int = 3) -> List[Dict]:
        """Get the next targets to investigate based on active focuses"""
        targets = []
        
        for focus in sorted(self.active_focuses.values(), key=lambda f: f.priority, reverse=True):
            # First priority: follow up on leads
            for lead in focus.leads_to_follow[:2]:  # Top 2 leads per focus
                if isinstance(lead, dict):
                    targets.append({
                        'path': lead['path'],
                        'action': 'analyze_file' if self._is_file_path(lead['path']) else 'explore_directory',
                        'priority': focus.priority + 5,  # Boost for focus-driven analysis
                        'reason': f"Focus-driven: {lead['reason']}",
                        'focus_id': list(self.active_focuses.keys())[list(self.active_focuses.values()).index(focus)],
                        'focus_type': focus.focus_type
                    })
            
            # Second priority: explore related areas
            if focus.investigation_depth < 5:  # Prevent infinite depth
                related_paths = self._get_related_investigation_paths(focus)
                for path in related_paths[:2]:
                    targets.append({
                        'path': path,
                        'action': 'analyze_file' if self._is_file_path(path) else 'explore_directory',
                        'priority': focus.priority,
                        'reason': f"Focus expansion: investigating {focus.focus_type}",
                        'focus_id': list(self.active_focuses.keys())[list(self.active_focuses.values()).index(focus)],
                        'focus_type': focus.focus_type
                    })
            
            if len(targets) >= limit:
                break
        
        return targets[:limit]
    
    def should_trigger_reassessment(self, recent_findings: List[Dict]) -> bool:
        """Determine if new findings warrant immediate focus reassessment"""
        if not recent_findings:
            return False
        
        # Trigger on significant findings
        high_risk_findings = [f for f in recent_findings if f.get('risk_level') == 'high']
        if high_risk_findings:
            return True
        
        # Trigger if we found multiple related medium-risk findings
        medium_risk_count = len([f for f in recent_findings if f.get('risk_level') == 'medium'])
        if medium_risk_count >= 2:
            return True
        
        # Trigger if findings suggest a pattern
        if len(recent_findings) >= 3:
            return True
        
        return False
    
    def _manage_focus_capacity(self):
        """Ensure we don't have too many active focuses"""
        if len(self.active_focuses) <= self.max_concurrent_focuses:
            return
        
        # Identify focuses to retire
        sorted_focuses = sorted(
            self.active_focuses.items(),
            key=lambda item: (item[1].priority, item[1].last_updated)
        )
        
        # Retire the lowest priority, oldest focuses
        to_retire = sorted_focuses[:len(self.active_focuses) - self.max_concurrent_focuses]
        
        for focus_id, focus in to_retire:
            if focus.investigation_depth >= 2:  # Only retire if we've done some work
                focus.status = "completed"
                self.focus_history.append(focus)
                del self.active_focuses[focus_id]
                print(f"  [FOCUS_RETIRED] Completed focus: {focus.target} (depth: {focus.investigation_depth})")
    
    def _get_related_investigation_paths(self, focus: AnalysisFocus) -> List[str]:
        """Get paths that might be related to the current focus"""
        related_paths = []
        
        # Based on focus type, suggest related investigation areas
        if focus.focus_type == 'vulnerability':
            # Look for related security-sensitive files
            base_dir = str(Path(focus.target).parent)
            related_paths.extend([
                f"{base_dir}/auth",
                f"{base_dir}/security", 
                f"{base_dir}/validators",
                f"{base_dir}/middleware"
            ])
        
        elif focus.focus_type == 'dependency':
            # Look for import chains and dependent modules
            related_paths.extend([
                f"{Path(focus.target).stem}_utils.py",
                f"{Path(focus.target).stem}_config.py",
                str(Path(focus.target).parent / "utils"),
                str(Path(focus.target).parent / "helpers")
            ])
        
        elif focus.focus_type == 'data_flow':
            # Look for data processing and transformation files
            base_dir = str(Path(focus.target).parent)
            related_paths.extend([
                f"{base_dir}/models",
                f"{base_dir}/parsers",
                f"{base_dir}/processors",
                f"{base_dir}/handlers"
            ])
        
        return related_paths
    
    def _is_file_path(self, path: str) -> bool:
        """Determine if a path is likely a file"""
        return '.' in Path(path).name
    
    def get_focus_summary(self) -> Dict:
        """Get a summary of current analysis state"""
        return {
            'active_focuses': len(self.active_focuses),
            'total_findings': sum(len(getattr(f, 'key_findings', [])) for f in self.active_focuses.values()),
            'highest_priority': max([f.priority for f in self.active_focuses.values()], default=0),
            'focuses': [f.to_dict() for f in self.active_focuses.values()]
        }