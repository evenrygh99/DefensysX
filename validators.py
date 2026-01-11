# @even rygh
"""
Security-focused file validation utilities.
Every validation here prevents a specific attack vector.
"""
import io
from typing import BinaryIO, Optional, List
from fastapi import UploadFile, HTTPException, status

from config import settings


class FileValidator:
    """
    Validates uploaded files against security constraints.
    Fail-fast approach: reject at first violation.
    """
    
    @staticmethod
    async def validate_file_size(file: UploadFile) -> None:
        """
        Enforce maximum file size to prevent DoS via resource exhaustion.
        
        Security rationale:
        - Large files consume memory/CPU during processing
        - Attackers could upload massive files to exhaust server resources
        - 5MB is sufficient for most legitimate log samples
        
        Args:
            file: The uploaded file object
            
        Raises:
            HTTPException: If file exceeds size limit
        """
        # Read in chunks to avoid loading entire file into memory
        chunk_size = 8192
        total_size = 0
        
        # Store chunks temporarily to reconstruct file later
        chunks = []
        
        while chunk := await file.read(chunk_size):
            total_size += len(chunk)
            
            if total_size > settings.max_file_size_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File size exceeds maximum allowed size of {settings.max_file_size_bytes} bytes"
                )
            
            chunks.append(chunk)
        
        # Reset file pointer and reconstruct content
        await file.seek(0)
        return total_size
    
    @staticmethod
    def validate_encoding(content: bytes) -> str:
        """
        Validate that file is UTF-8 encoded text.
        
        Security rationale:
        - Binary files could contain executable code or exploits
        - Non-UTF-8 text could bypass parsing logic and cause crashes
        - Explicit encoding requirement prevents encoding-based attacks
        
        Args:
            content: Raw file bytes
            
        Returns:
            Decoded UTF-8 string
            
        Raises:
            HTTPException: If file is not valid UTF-8 text
        """
        try:
            # Attempt UTF-8 decode with strict error handling
            decoded = content.decode('utf-8', errors='strict')
            return decoded
        except UnicodeDecodeError as e:
            # Provide helpful error message
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File must be UTF-8 encoded text. Invalid byte at position {e.start}."
            )
    
    @staticmethod
    def validate_content_type(file: UploadFile) -> None:
        """
        Validate MIME type is text-related or acceptable binary format.
        
        Security rationale:
        - Accept text/plain, application/octet-stream, and text/* variants
        - Also accept None (when browser doesn't set content-type)
        - MIME type is first line of defense (note: can be spoofed, so we validate content too)
        - Content validation ensures file is actually text, regardless of MIME type
        
        Args:
            file: The uploaded file object
            
        Raises:
            HTTPException: If MIME type is not allowed
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Validating content type: {file.content_type} | filename: {file.filename}")
        
        # Allow None (no content-type set), text/*, and octet-stream
        if file.content_type is None:
            return  # Accept when browser doesn't set content-type
        
        if file.content_type in settings.allowed_mime_types:
            return  # Explicitly allowed
        
        if file.content_type.startswith('text/'):
            return  # Accept any text/* MIME type
        
        # Reject everything else
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Only text files are accepted. Received: {file.content_type}"
        )
    
    @staticmethod
    def validate_log_type(log_type: str) -> str:
        """
        Validate log type against whitelist.
        
        Security rationale:
        - Whitelist approach: only accept known, safe log formats
        - Prevents injection of arbitrary "log type" values that could affect parsing
        - Each log type has a specific, validated parser
        
        Args:
            log_type: User-provided log type string
            
        Returns:
            Validated (lowercase) log type
            
        Raises:
            HTTPException: If log type is not in whitelist
        """
        log_type_lower = log_type.lower().strip()
        
        if log_type_lower not in settings.allowed_log_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid log type. Allowed types: {', '.join(settings.allowed_log_types)}"
            )
        
        return log_type_lower

    @staticmethod
    def auto_detect_log_type(lines: List[str], max_lines: int = 50) -> str:
        """Heuristically detect log type by trying known parsers.

        Returns one of settings.allowed_log_types.
        """
        from parsers import LogParserFactory

        preferred_order = ["ssh", "nginx", "apache"]
        candidates = [t for t in preferred_order if t in settings.allowed_log_types]
        candidates.extend([t for t in settings.allowed_log_types if t not in candidates])

        scores = {t: 0 for t in candidates}
        sample = [ln for ln in lines[:max_lines] if ln and ln.strip()]

        for log_type in candidates:
            try:
                parser = LogParserFactory.get_parser(log_type)
            except Exception:
                continue

            for idx, line in enumerate(sample, start=1):
                try:
                    if parser.parse_line(line, idx) is not None:
                        scores[log_type] += 1
                except Exception:
                    continue

        best_type = max(candidates, key=lambda t: (scores.get(t, 0), -candidates.index(t)))
        if scores.get(best_type, 0) <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to auto-detect log type from content. Please specify log_type explicitly.",
            )
        return best_type
    
    @staticmethod
    def validate_line_constraints(content: str) -> list[str]:
        """
        Validate line count and line length constraints.
        
        Security rationale:
        - Extremely long lines can cause buffer overflows or DoS in regex parsers
        - Too many lines can exhaust memory during processing
        - Attackers could craft malicious logs with pathological characteristics
        
        Args:
            content: Full file content as string
            
        Returns:
            List of validated lines
            
        Raises:
            HTTPException: If constraints are violated
        """
        lines = content.splitlines()
        
        # Check total line count
        if len(lines) > settings.max_lines_per_file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File contains {len(lines)} lines. Maximum allowed: {settings.max_lines_per_file}"
            )
        
        # Check individual line lengths
        for line_num, line in enumerate(lines, start=1):
            if len(line) > settings.max_line_length:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Line {line_num} exceeds maximum length of {settings.max_line_length} characters"
                )
        
        return lines
    
    @staticmethod
    def detect_binary_content(content: bytes, sample_size: int = 8192) -> bool:
        """
        Detect if content appears to be binary data.
        
        Security rationale:
        - Binary files could contain malware, exploits, or executable code
        - Even if MIME type claims text/plain, content might be binary
        - This is defense-in-depth: verify content matches claimed type
        
        Args:
            content: Raw file bytes
            sample_size: Number of bytes to sample for detection
            
        Returns:
            True if content appears binary, False if text
        """
        # Sample first N bytes
        sample = content[:sample_size]
        
        # Check for null bytes (strong indicator of binary data)
        if b'\x00' in sample:
            return True
        
        # Check for high ratio of non-printable characters
        non_printable = sum(1 for byte in sample if byte < 32 and byte not in (9, 10, 13))
        
        # If more than 30% non-printable, likely binary
        if len(sample) > 0 and (non_printable / len(sample)) > 0.3:
            return True
        
        return False


class StreamingFileValidator:
    """
    Validates files while streaming to avoid loading entire file into memory.
    More efficient for large files that approach size limits.
    """
    
    def __init__(self):
        self.total_bytes = 0
        self.total_lines = 0
        self.buffer = ""
    
    async def validate_chunk(self, chunk: bytes) -> list[str]:
        """
        Validate a chunk of file data as it's streamed.
        
        Returns completed lines from this chunk.
        Incomplete lines are buffered for next chunk.
        """
        # Check size limit
        self.total_bytes += len(chunk)
        if self.total_bytes > settings.max_file_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File size exceeds maximum of {settings.max_file_size_bytes} bytes"
            )
        
        # Check for binary content
        if FileValidator.detect_binary_content(chunk):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Binary content detected. Only text files are allowed."
            )
        
        # Decode chunk
        try:
            decoded = chunk.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be valid UTF-8 encoded text"
            )
        
        # Add to buffer and extract complete lines
        self.buffer += decoded
        lines = self.buffer.split('\n')
        
        # Keep last incomplete line in buffer
        self.buffer = lines[-1]
        complete_lines = lines[:-1]
        
        # Validate each complete line
        for line in complete_lines:
            self.total_lines += 1
            
            if self.total_lines > settings.max_lines_per_file:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File exceeds maximum of {settings.max_lines_per_file} lines"
                )
            
            if len(line) > settings.max_line_length:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Line {self.total_lines} exceeds maximum length of {settings.max_line_length} characters"
                )
        
        return complete_lines
    
    def finalize(self) -> list[str]:
        """
        Process any remaining buffered data after stream completes.
        Returns final incomplete line if any.
        """
        if self.buffer:
            if len(self.buffer) > settings.max_line_length:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Final line exceeds maximum length of {settings.max_line_length} characters"
                )
            return [self.buffer]
        return []
