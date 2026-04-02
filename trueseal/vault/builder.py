import os
import gzip
import stat
from pathlib import Path

class AegisForge:
    """Build vault from files on disk"""
    
    def __init__(self, root_path, exclude_patterns=None, compression='gzip', explicit_targets=None, max_depth=100):
        self.root_path = Path(root_path).resolve()
        self.exclude_patterns = exclude_patterns or []
        self.compression = compression
        self.explicit_targets = [Path(p).resolve() for p in explicit_targets] if explicit_targets else None
        self.max_depth = max_depth
        self.files = []
    
    def collect_files(self):
        """Walk directory and collect files to seal"""
        spec = self._load_ignore_patterns()
        
        if self.explicit_targets:
            for target in self.explicit_targets:
                if not target.exists():
                    continue
                if target.is_symlink():
                    continue
                    
                if target.is_file():
                    self._forge_payload_if_not_ignored(target, spec)
                elif target.is_dir():
                    self._walk_and_collect(target, spec)
        else:
            self._walk_and_collect(self.root_path, spec)
        
        return self.files

    def _walk_and_collect(self, base_dir, spec):
        for root, dirs, filenames in os.walk(str(base_dir)):
            root_path = Path(str(root))
            
            # Anti Zip-Bomb / Symlink Loop
            depth = len(root_path.relative_to(self.root_path).parts) if self.root_path in root_path.parents else len(root_path.parts)
            if depth > self.max_depth:
                dirs.clear()
                continue
                
            # Filter ignored directories (must add trailing slash for pathspec directory matching)
            dirs[:] = [
                d for d in dirs 
                if not spec.match_file(self._get_rel_posix(root_path / str(d), self.root_path) + '/')
            ]
            
            for filename in filenames:
                filepath = root_path / str(filename)
                if filepath.is_symlink():
                    continue
                
                self._forge_payload_if_not_ignored(filepath, spec)

    def _forge_payload_if_not_ignored(self, filepath, spec):
        try:
            rel_path = filepath.relative_to(self.root_path)
            rel_str = self._get_rel_posix(filepath, self.root_path)
        except ValueError:
            rel_path = Path(filepath.name)
            rel_str = filepath.name
            
        if spec.match_file(rel_str):
            return
            
        self.files.append({
            'path': filepath,
            'rel_path': str(rel_path).replace('\\', '/'),
            'size': filepath.stat().st_size,
            'permissions': stat.S_IMODE(filepath.stat().st_mode)
        })

    def _get_rel_posix(self, path, base):
        path = Path(path)
        base = Path(base)
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            return path.name

    def compress_file(self, data):
        """Compress file data"""
        if self.compression == 'none':
            return data
        elif self.compression == 'gzip':
            return gzip.compress(data, compresslevel=6)
        elif self.compression == 'brotli':
            try:
                import brotli
                return brotli.compress(data, quality=6)
            except ImportError:
                raise ImportError("Brotli compression was requested, but the 'brotli' package is not installed. Install it with 'pip install trueseal[brotli]'.")
        else:
            return data
    
    def _load_ignore_patterns(self):
        """Load patterns from .sealignore and .gitignore"""
        patterns = list(self.exclude_patterns)
        
        for ignore_file in ['.sealignore', '.gitignore']:
            ignore_path = self.root_path / ignore_file
            if ignore_path.exists() and ignore_path.is_file():
                with open(ignore_path, 'r', encoding='utf-8') as f:
                    patterns.extend(f.read().splitlines())
                    
        # Strict enforcement of pathspec to avoid dangerous false negatives with raw fnmatch
        try:
            import pathspec
            return pathspec.PathSpec.from_lines('gitwildmatch', patterns)
        except ImportError:
            class DummySpec:
                def __init__(self, pats):
                    import fnmatch
                    self.pats = pats
                    self.fnmatch = fnmatch
                def match_file(self, filename):
                    for pat in self.pats:
                        if not pat or pat.startswith('#'): continue
                        if self.fnmatch.fnmatch(filename, pat.strip('/')): return True
                    return False
            return DummySpec(patterns)
        # Fallback to primitive glob matching if pathspec is not available
