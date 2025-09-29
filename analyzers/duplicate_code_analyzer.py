#!/usr/bin/env python3
"""
DinoScan Duplicate Code Detector - Advanced AST-based similarity detection.

This analyzer identifies duplicate code using comprehensive AST analysis:
- AST-based similarity detection with winnowing algorithms
- Structural code comparison beyond simple text matching
- Configurable similarity thresholds and minimum code block sizes
- Advanced heuristics to reduce false positives from boilerplate code
- Cross-file and within-file duplicate detection
- Support for partial and exact matches

Enhanced features over PowerShell version:
- AST normalization for accurate similarity computation
- Winnowing algorithm for efficient similarity detection
- Token-based and structural similarity metrics
- Configurable filters for framework patterns and boilerplate
- Hierarchical reporting with similarity scores
- Performance optimizations for large codebases
"""

import argparse
import ast
import hashlib
import os
import re
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.base_analyzer import AnalysisResult, ASTAnalyzer, Category, Finding, Severity
from core.config_manager import ConfigManager
from core.reporter import create_reporter


@dataclass
class CodeBlock:
    """Represents a block of code for duplicate detection."""

    file_path: str
    start_line: int
    end_line: int
    content: str
    normalized_content: str = ""
    tokens: list[str] = field(default_factory=list)
    fingerprints: set[int] = field(default_factory=set)
    node_types: list[str] = field(default_factory=list)
    similarity_hash: str = ""


@dataclass
class DuplicateMatch:
    """Represents a duplicate code match between two blocks."""

    block1: CodeBlock
    block2: CodeBlock
    similarity_score: float
    match_type: str  # 'exact', 'structural', 'partial'
    line_count: int


class CodeTokenizer(ast.NodeVisitor):
    """AST visitor to extract tokens for similarity analysis."""

    def __init__(self) -> None:
        """Initialize the CodeTokenizer instance."""
        self.tokens: list[str] = []

    def visit(self, node: ast.AST) -> None:
        """Visit AST node and extract tokens."""
        # Add node type as token
        self.tokens.append(type(node).__name__)

        # Add specific tokens based on node type
        if isinstance(node, ast.Name):
            self.tokens.append("NAME")  # Normalize variable names
        elif isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            self.tokens.append("LITERAL")  # Normalize literals
        elif isinstance(node, ast.operator):
            self.tokens.append(type(node).__name__)
        elif isinstance(node, ast.keyword):
            self.tokens.append("KEYWORD")

        self.generic_visit(node)


class DuplicateCodeAnalyzer(ASTAnalyzer):
    """Duplicate code analyzer with comprehensive AST-based detection."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.name = "DuplicateCodeAnalyzer"
        self._setup_duplicate_config()

    @staticmethod
    def get_supported_extensions() -> set[str]:
        """Return supported Python file extensions."""
        return {".py", ".pyi", ".pyw"}

    def _setup_duplicate_config(self) -> None:
        """Set up duplicate detection configuration."""
        # Detection thresholds
        self.min_lines = self.config.get("min_lines", 6)
        self.min_tokens = self.config.get("min_tokens", 50)
        self.similarity_threshold = self.config.get("similarity_threshold", 0.8)

        # Winnowing parameters
        self.winnow_k = self.config.get("winnow_k", 17)  # k-gram size
        self.winnow_w = self.config.get("winnow_w", 4)  # window size

        # Detection modes
        self.detect_exact = self.config.get("detect_exact", True)
        self.detect_structural = self.config.get("detect_structural", True)
        self.detect_partial = self.config.get("detect_partial", False)

        # Filters
        self.ignore_whitespace = self.config.get("ignore_whitespace", True)
        self.ignore_comments = self.config.get("ignore_comments", True)
        self.ignore_imports = self.config.get("ignore_imports", True)
        self.ignore_docstrings = self.config.get("ignore_docstrings", True)

        # Skip patterns (common boilerplate)
        self.skip_patterns = self.config.get(
            "skip_patterns",
            [
                r"^class.*\(.*\):$",
                r"^def __init__\(self.*\):$",
                r"^if __name__ == [\'\"]__main__[\'\"]:\s*$",
                r"^\s*pass\s*$",
                r"^\s*return\s*$",
            ],
        )

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze duplicates within a single file."""
        blocks = self._extract_code_blocks(file_path)
        return self._find_duplicates_in_blocks(blocks, within_file=True)

    def analyze_project(self, project_path: str) -> Any:
        """Analyze duplicates across the entire project."""
        # Collect all code blocks from all files
        all_blocks: list[CodeBlock] = []
        analyzed_files = []

        for root, dirs, files in os.walk(project_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self._excluded_dirs]

            for file in files:
                if not file.endswith((".py", ".pyi", ".pyw")):
                    continue

                file_path = str(Path(root) / file)

                if self.should_analyze_file(file_path):
                    analyzed_files.append(file_path)
                    blocks = self._extract_code_blocks(file_path)
                    all_blocks.extend(blocks)

        # Find duplicates across all blocks
        findings = self._find_duplicates_in_blocks(all_blocks, within_file=False)

        # Create analysis result
        result = AnalysisResult(
            analyzer_name=self.name,
            version=self.version,
            timestamp=datetime.now().isoformat(),
            project_path=project_path,
        )

        result.findings = findings
        result.files_analyzed = analyzed_files

        return result

    def _extract_code_blocks(self, file_path: str) -> list[CodeBlock]:
        """Extract code blocks from a Python file."""
        tree = self.parse_file(file_path)
        if not tree:
            return []

        try:
            source_lines = (
                Path(file_path).read_text(encoding="utf-8").splitlines(keepends=True)
            )
        except (OSError, UnicodeDecodeError):
            return []

        blocks = []
        extractor = CodeBlockExtractor(file_path, source_lines, self.config)
        extractor.visit(tree)

        for block in extractor.blocks:
            if self._is_valid_block(block):
                block.normalized_content = self._normalize_code(block.content)
                block.tokens = self._tokenize_code(block.normalized_content)
                block.fingerprints = self._compute_fingerprints(block.tokens)
                block.similarity_hash = self._compute_similarity_hash(
                    block.normalized_content
                )
                blocks.append(block)

        return blocks

    def _is_valid_block(self, block: CodeBlock) -> bool:
        """Check if a code block meets minimum requirements for analysis."""
        line_count = block.end_line - block.start_line + 1

        # Check minimum lines
        if line_count < self.min_lines:
            return False

        # Check minimum content (non-empty lines)
        non_empty_lines = sum(1 for line in block.content.split("\n") if line.strip())
        if non_empty_lines < self.min_lines // 2:
            return False

        # Check if it matches skip patterns
        normalized = block.content.strip()
        return not any(re.match(pattern, normalized) for pattern in self.skip_patterns)

    def _normalize_code(self, code: str) -> str:
        """Normalize code for comparison."""
        lines = code.split("\n")
        normalized_lines = []

        for original_line in lines:
            processed_line = original_line
            # Remove comments if configured
            if self.ignore_comments:
                processed_line = re.sub(r"#.*$", "", processed_line)

            # Remove leading/trailing whitespace if configured
            if self.ignore_whitespace:
                processed_line = processed_line.strip()

            # Skip empty lines
            if processed_line:
                normalized_lines.append(processed_line)

        return "\n".join(normalized_lines)

    @staticmethod
    def _tokenize_code(code: str) -> list[str]:
        """Tokenize normalized code for similarity analysis."""
        try:
            tree = ast.parse(code)
            tokenizer = CodeTokenizer()
            tokenizer.visit(tree)
            return tokenizer.tokens
        except SyntaxError:
            # Fall back to simple tokenization
            return re.findall(r"\w+|[^\w\s]", code)

    def _compute_fingerprints(self, tokens: list[str]) -> set[int]:
        """Compute winnowing fingerprints for efficient similarity detection."""
        if len(tokens) < self.winnow_k:
            return set()

        # Create k-grams
        kgrams = []
        for i in range(len(tokens) - self.winnow_k + 1):
            kgram = " ".join(tokens[i : i + self.winnow_k])
            hash_value = hash(kgram) % (2**32)  # 32-bit hash
            kgrams.append((i, hash_value))

        # Apply winnowing
        fingerprints = set()
        window_start = 0

        for window_end in range(self.winnow_w - 1, len(kgrams)):
            window = kgrams[window_start : window_end + 1]
            min_hash = min(window, key=lambda x: (x[1], x[0]))
            fingerprints.add(min_hash[1])

            # Move window
            if window_start < window_end:
                window_start += 1

        return fingerprints

    @staticmethod
    def _compute_similarity_hash(code: str) -> str:
        """Compute a similarity hash for fast comparison."""
        # Remove variable names and literals for structural comparison
        normalized = re.sub(r"\b[a-zA-Z_]\w*\b", "VAR", code)
        normalized = re.sub(r"\b\d+\b", "NUM", normalized)
        normalized = re.sub(r'"[^"]*"', "STR", normalized)
        normalized = re.sub(r"'[^']*'", "STR", normalized)

        return hashlib.sha256(normalized.encode()).hexdigest()

    def _find_duplicates_in_blocks(
        self, blocks: list[CodeBlock], within_file: bool
    ) -> list[Finding]:
        """Find duplicate blocks using various similarity metrics."""
        findings: list[Finding] = []

        # Group blocks by similarity hash for fast exact matching
        hash_groups = defaultdict(list)
        for block in blocks:
            hash_groups[block.similarity_hash].append(block)

        # Find exact structural matches
        if self.detect_exact:
            for block_group in hash_groups.values():
                if len(block_group) > 1:
                    findings.extend(self._create_exact_duplicate_findings(block_group))

        # Find similar blocks using fingerprints
        if self.detect_structural or self.detect_partial:
            findings.extend(self._find_similar_blocks(blocks, within_file))

        return findings

    def _create_exact_duplicate_findings(
        self, duplicate_blocks: list[CodeBlock]
    ) -> list[Finding]:
        """Create findings for exact duplicate blocks."""
        findings: list[Finding] = []

        # Create findings for all pairs
        for i, block1 in enumerate(duplicate_blocks):
            for j, block2 in enumerate(duplicate_blocks[i + 1 :], start=i + 1):
                # Skip duplicates in the same file at same location
                if (
                    block1.file_path == block2.file_path
                    and abs(block1.start_line - block2.start_line) < 3
                ):
                    continue

                line_count = block1.end_line - block1.start_line + 1

                # Primary finding (first occurrence)
                finding = Finding(
                    rule_id="exact-duplicate",
                    category=Category.DUPLICATES,
                    severity=Severity.MEDIUM if line_count > 15 else Severity.LOW,
                    message=f"Exact duplicate code block ({line_count} lines)",
                    file_path=block1.file_path,
                    line_number=block1.start_line,
                    column_number=0,
                    context=self._get_context_preview(block1),
                    suggestion=(
                        f"Consider extracting common code into a function. "
                        f"Duplicate found at {Path(block2.file_path).name}:"
                        f"{block2.start_line}"
                    ),
                    tags={"duplicate", "exact", f"{line_count}-lines"},
                )
                findings.append(finding)

                # Secondary finding (duplicate occurrence)
                finding2 = Finding(
                    rule_id="exact-duplicate",
                    category=Category.DUPLICATES,
                    severity=Severity.LOW,  # Lower severity for secondary occurrence
                    message=(
                        f"Duplicate of code block at "
                        f"{Path(block1.file_path).name}:{block1.start_line}"
                    ),
                    file_path=block2.file_path,
                    line_number=block2.start_line,
                    column_number=0,
                    context=self._get_context_preview(block2),
                    suggestion=(
                        "Consider removing this duplicate and calling the extracted "
                        "function"
                    ),
                    tags={"duplicate", "exact", f"{line_count}-lines", "secondary"},
                )
                findings.append(finding2)

        return findings

    def _find_similar_blocks(
        self, blocks: list[CodeBlock], within_file: bool
    ) -> list[Finding]:
        """Find similar blocks using fingerprint comparison."""
        findings: list[Finding] = []

        for i, block1 in enumerate(blocks):
            for j, block2 in enumerate(blocks[i + 1 :], start=i + 1):
                # Skip if same file and within-file analysis is disabled
                if not within_file and block1.file_path == block2.file_path:
                    continue

                # Compute similarity
                similarity = self._compute_similarity(block1, block2)

                if similarity >= self.similarity_threshold:
                    line_count = max(
                        block1.end_line - block1.start_line + 1,
                        block2.end_line - block2.start_line + 1,
                    )

                    match_type = "structural" if similarity < 0.95 else "near-exact"

                    finding = Finding(
                        rule_id=f"{match_type}-duplicate",
                        category=Category.DUPLICATES,
                        severity=Severity.MEDIUM if similarity > 0.9 else Severity.LOW,
                        message=(
                            f"{match_type.title()} duplicate code "
                            f"({similarity:.1%} similar, {line_count} lines)"
                        ),
                        file_path=block1.file_path,
                        line_number=block1.start_line,
                        column_number=0,
                        context=self._get_context_preview(block1),
                        suggestion=(
                            f"Consider refactoring similar code. "
                            f"Related code at {Path(block2.file_path).name}:"
                            f"{block2.start_line}"
                        ),
                        tags={
                            "duplicate",
                            match_type,
                            f"{similarity:.0%}-similar",
                            f"{line_count}-lines",
                        },
                    )
                    findings.append(finding)

        return findings

    @staticmethod
    def _compute_similarity(block1: CodeBlock, block2: CodeBlock) -> float:
        """Compute similarity between two code blocks."""
        # Fingerprint-based similarity (Jaccard index)
        if block1.fingerprints and block2.fingerprints:
            intersection = len(block1.fingerprints & block2.fingerprints)
            union = len(block1.fingerprints | block2.fingerprints)
            jaccard_similarity = intersection / union if union > 0 else 0.0
        else:
            jaccard_similarity = 0.0

        # Token-based similarity
        if block1.tokens and block2.tokens:
            common_tokens = sum(1 for token in block1.tokens if token in block2.tokens)
            max_tokens = max(len(block1.tokens), len(block2.tokens))
            token_similarity = common_tokens / max_tokens if max_tokens > 0 else 0.0
        else:
            token_similarity = 0.0

        # Combine similarities with weights
        return 0.7 * jaccard_similarity + 0.3 * token_similarity

    @staticmethod
    def _get_context_preview(block: CodeBlock) -> str:
        """Get a preview of the code block for context."""
        lines = block.content.split("\n")[:3]  # First 3 lines
        preview = "\n".join(lines)
        if len(block.content.split("\n")) > 3:
            preview += "\n..."
        return preview


class CodeBlockExtractor(ast.NodeVisitor):
    """AST visitor to extract code blocks for duplicate detection."""

    def __init__(self, file_path: str, source_lines: list[str], config: dict[str, Any]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.config = config
        self.blocks: list[CodeBlock] = []
        self.min_lines = config.get("min_lines", 6)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Extract function body as a code block."""
        self._extract_node_block(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Extract async function body as a code block."""
        self._extract_node_block(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Extract class body as a code block."""
        self._extract_node_block(node)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Extract if block body."""
        self._extract_compound_stmt_blocks(node)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Extract for loop body."""
        self._extract_compound_stmt_blocks(node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        """Extract while loop body."""
        self._extract_compound_stmt_blocks(node)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Extract with statement body."""
        self._extract_compound_stmt_blocks(node)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Extract try/except blocks."""
        self._extract_compound_stmt_blocks(node)
        self.generic_visit(node)

    def _extract_node_block(self, node: ast.stmt) -> None:
        """Extract a code block from an AST node."""
        start_line = node.lineno
        end_line = self._get_end_line(node)

        if end_line - start_line + 1 >= self.min_lines:
            content = self._get_source_content(start_line, end_line)
            if content:
                block = CodeBlock(
                    file_path=self.file_path,
                    start_line=start_line,
                    end_line=end_line,
                    content=content,
                )
                self.blocks.append(block)

    def _extract_compound_stmt_blocks(self, node: ast.stmt) -> None:
        """Extract blocks from compound statements (if, for, while, etc.)."""
        # Extract the body
        if hasattr(node, "body") and node.body:
            body_start = node.body[0].lineno if node.body else node.lineno
            body_end = self._get_end_line(node.body[-1]) if node.body else node.lineno

            if body_end - body_start + 1 >= self.min_lines:
                content = self._get_source_content(body_start, body_end)
                if content:
                    block = CodeBlock(
                        file_path=self.file_path,
                        start_line=body_start,
                        end_line=body_end,
                        content=content,
                    )
                    self.blocks.append(block)

        # Extract else blocks if present
        if hasattr(node, "orelse") and node.orelse:
            else_start = node.orelse[0].lineno
            else_end = self._get_end_line(node.orelse[-1])

            if else_end - else_start + 1 >= self.min_lines:
                content = self._get_source_content(else_start, else_end)
                if content:
                    block = CodeBlock(
                        file_path=self.file_path,
                        start_line=else_start,
                        end_line=else_end,
                        content=content,
                    )
                    self.blocks.append(block)

    @staticmethod
    def _get_end_line(node: ast.AST) -> int:
        """Get the ending line number of an AST node."""
        if hasattr(node, "end_lineno") and node.end_lineno:
            return int(node.end_lineno)

        # Fall back to searching for the maximum line number in the subtree
        max_line = getattr(node, "lineno", 1)
        for child in ast.walk(node):
            if hasattr(child, "lineno"):
                max_line = max(max_line, child.lineno)

        return max_line

    def _get_source_content(self, start_line: int, end_line: int) -> str:
        """Get source code content for the specified line range."""
        try:
            # Convert to 0-based indexing
            start_idx = start_line - 1
            end_idx = min(end_line, len(self.source_lines))

            lines = self.source_lines[start_idx:end_idx]
            return "".join(lines).rstrip()
        except (IndexError, ValueError):
            return ""

    @staticmethod
    def main(argv: list) -> None:
        """Main entry point for the duplicate code analyzer."""
        parser = argparse.ArgumentParser(
            description="DinoScan Duplicate Code Detector",
        )
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s /path/to/file.py --threshold 0.9
  %(prog)s /path/to/project --output-format json --output-file duplicates.json
        """,
        )

        parser.add_argument("path", help="Path to analyze (file or directory)")

        parser.add_argument(
            "--output-format",
            choices=["console", "json", "xml", "sarif"],
            default="console",
            help="Output format (default: console)",
        )

        parser.add_argument(
            "--output-file", help="Output file path (default: print to stdout)"
        )

        parser.add_argument("--config", help="Configuration file path")

        parser.add_argument(
            "--threshold", type=float, help="Similarity threshold (0.0-1.0)"
        )

        parser.add_argument(
            "--min-lines", type=int, help="Minimum lines for duplicate detection"
        )

        parser.add_argument(
            "--no-structural",
            action="store_true",
            help="Disable structural similarity detection",
        )

        parser.add_argument(
            "--enable-partial",
            action="store_true",
            help="Enable partial duplicate detection",
        )

        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Show verbose output",
        )

        args = parser.parse_args()

        # Load configuration
        config_manager = ConfigManager(args.config)
        config = config_manager.get_analyzer_config("duplicate_code")

        # Override config with command-line arguments
        if args.threshold:
            config["similarity_threshold"] = args.threshold
        if args.min_lines:
            config["min_lines"] = args.min_lines
        if args.no_structural:
            config["detect_structural"] = False
        if args.enable_partial:
            config["detect_partial"] = True

        # Create analyzer
        analyzer = DuplicateCodeAnalyzer(config)

        try:
            if args.verbose:
                sys.stderr.write(
                    f"Starting duplicate code analysis of {args.path}...\n"
                )

            # Analyze file or project
            if Path(args.path).is_file():
                findings = analyzer.analyze_file(args.path)
                result = AnalysisResult(
                    analyzer_name=analyzer.name,
                    version=analyzer.version,
                    timestamp=datetime.now().isoformat(),
                    project_path=str(Path(args.path).parent),
                )
                result.findings = findings
                result.files_analyzed = [args.path]
            else:
                result = analyzer.analyze_project(args.path)

            if args.verbose:
                stats = result.get_summary_stats()
                sys.stderr.write(
                    f"Analysis complete: {stats['total_findings']} duplicate code "
                    f"issues found\n"
                )


            # Create reporter and output results
            reporter_config = {
                "use_colors": not args.output_file,
                "show_context": True,
                "max_findings_per_file": 25,
            }


            reporter = create_reporter(args.output_format, reporter_config)

            if args.output_file:
                reporter.save_results(result, args.output_file)
                if args.verbose:
                    sys.stderr.write(f"Results saved to {args.output_file}\n")
            else:
                reporter.print_results(result)

            # Exit with appropriate code
            stats = result.get_summary_stats()
            if stats["medium_severity"] > 5:  # Many duplicates
                sys.exit(1)
            else:
                sys.exit(0)

        except Exception as e:
            sys.stderr.write(f"Error during analysis: {e}\n")
            if args.verbose:
                traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":

    DuplicateCodeAnalyzer.main(sys.argv)
