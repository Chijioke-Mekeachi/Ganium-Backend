package telemetry

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
	LogLevelAudit LogLevel = "AUDIT"
)

// Logger provides structured JSON logging with built-in secret redaction.
type Logger struct {
	mu     sync.Mutex
	writer io.Writer
	env    string
}

var (
	defaultLogger *Logger
	once          sync.Once

	// Secret patterns to redact
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`),
		regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token|jwt|seed[_-]?phrase|private[_-]?key)\s*[:=]\s*["']?([^"'\s]+)["']?`),
		regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`), // 64-char hex strings (often private keys or API secrets)
	}
)

func GetLogger() *Logger {
	once.Do(func() {
		defaultLogger = &Logger{
			writer: os.Stdout,
			env:    os.Getenv("APP_ENV"),
		}
	})
	return defaultLogger
}

type LogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     LogLevel       `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

func (l *Logger) log(level LogLevel, msg string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cleanedMsg := RedactSensitiveString(msg)
	cleanedFields := make(map[string]any, len(fields))
	for k, v := range fields {
		if isSensitiveKey(k) {
			cleanedFields[k] = "[REDACTED]"
		} else if strVal, ok := v.(string); ok {
			cleanedFields[k] = RedactSensitiveString(strVal)
		} else {
			cleanedFields[k] = v
		}
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Message:   cleanedMsg,
		Fields:    cleanedFields,
	}

	data, err := json.Marshal(entry)
	if err == nil {
		fmt.Fprintln(l.writer, string(data))
	}
}

func (l *Logger) Info(msg string, fields ...map[string]any) {
	l.log(LogLevelInfo, msg, mergeFields(fields...))
}

func (l *Logger) Warn(msg string, fields ...map[string]any) {
	l.log(LogLevelWarn, msg, mergeFields(fields...))
}

func (l *Logger) Error(msg string, fields ...map[string]any) {
	l.log(LogLevelError, msg, mergeFields(fields...))
}

func (l *Logger) Debug(msg string, fields ...map[string]any) {
	l.log(LogLevelDebug, msg, mergeFields(fields...))
}

func (l *Logger) Audit(action string, userID string, target string, verdict string, fields ...map[string]any) {
	f := mergeFields(fields...)
	f["action"] = action
	f["user_id"] = userID
	f["target"] = target
	f["verdict"] = verdict
	l.log(LogLevelAudit, fmt.Sprintf("AUDIT: %s by %s on target %s -> %s", action, userID, target, verdict), f)
}

func mergeFields(fields ...map[string]any) map[string]any {
	result := make(map[string]any)
	for _, f := range fields {
		for k, v := range f {
			result[k] = v
		}
	}
	return result
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	return strings.Contains(lower, "key") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "auth") ||
		strings.Contains(lower, "credential") ||
		strings.Contains(lower, "seed")
}

// RedactSensitiveString redacts known secret patterns from output strings.
func RedactSensitiveString(s string) string {
	for _, pattern := range secretPatterns {
		s = pattern.ReplaceAllString(s, "[REDACTED_SECRET]")
	}
	return s
}
