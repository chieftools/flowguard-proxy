package middleware

import (
	"mime"
	"net/http"
	"path"
	"strings"
)

type RequestLogEntryResponseResourceInfo struct {
	Type            string `json:"type"`
	Source          string `json:"source"`
	StaticCandidate bool   `json:"static_candidate"`
	MIME            string `json:"mime,omitempty"`
	Extension       string `json:"extension,omitempty"`
}

func classifyResponseResource(r *http.Request, headers map[string][]string) RequestLogEntryResponseResourceInfo {
	mimeType := normalizeMediaType(headerValue(headers, "Content-Type"))
	extension := requestPathExtension(r)

	if mimeType != "" {
		if resourceType, ok := resourceTypeFromMIME(mimeType); ok {
			return responseResourceInfo(resourceType, "content-type", mimeType, extension)
		}
	}

	fetchDest := ""
	if r != nil {
		fetchDest = strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")))
	}
	if fetchDest != "" {
		if resourceType, ok := resourceTypeFromFetchDest(fetchDest); ok {
			return responseResourceInfo(resourceType, "sec-fetch-dest", mimeType, extension)
		}
		if fetchDest != "empty" {
			return responseResourceInfo("other", "sec-fetch-dest", mimeType, extension)
		}
	}

	if extension != "" {
		if resourceType, ok := resourceTypeFromExtension(extension); ok {
			return responseResourceInfo(resourceType, "path-extension", mimeType, extension)
		}
		return responseResourceInfo("other", "path-extension", mimeType, extension)
	}

	if mimeType != "" {
		return responseResourceInfo("other", "content-type", mimeType, extension)
	}

	return responseResourceInfo("unknown", "none", "", "")
}

func responseResourceInfo(resourceType, source, mimeType, extension string) RequestLogEntryResponseResourceInfo {
	return RequestLogEntryResponseResourceInfo{
		Type:            resourceType,
		Source:          source,
		StaticCandidate: isStaticResourceCandidate(resourceType),
		MIME:            mimeType,
		Extension:       extension,
	}
}

func normalizeMediaType(contentType string) string {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return ""
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}

	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	if !strings.Contains(mediaType, "/") {
		return ""
	}

	return mediaType
}

func headerValue(headers map[string][]string, name string) string {
	for key, values := range headers {
		if !strings.EqualFold(key, name) || len(values) == 0 {
			continue
		}
		return values[0]
	}

	return ""
}

func requestPathExtension(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}

	extension := strings.TrimPrefix(strings.ToLower(path.Ext(r.URL.Path)), ".")
	if extension == "" || strings.Contains(extension, "/") {
		return ""
	}

	return extension
}

func resourceTypeFromMIME(mimeType string) (string, bool) {
	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return "image", true
	case strings.HasPrefix(mimeType, "font/"):
		return "font", true
	case strings.HasPrefix(mimeType, "audio/"), strings.HasPrefix(mimeType, "video/"):
		return "media", true
	}

	switch mimeType {
	case "text/html", "application/xhtml+xml":
		return "html", true
	case "text/css":
		return "stylesheet", true
	case "application/ecmascript", "application/javascript", "application/wasm", "application/x-javascript", "text/ecmascript", "text/javascript":
		return "script", true
	case "application/json":
		return "json", true
	case "application/xml", "text/xml":
		return "xml", true
	case "text/csv", "text/markdown", "text/plain":
		return "text", true
	case "application/font-woff", "application/font-woff2", "application/vnd.ms-fontobject", "application/x-font-opentype", "application/x-font-ttf", "application/x-font-woff", "application/x-font-woff2":
		return "font", true
	case "application/gzip", "application/vnd.rar", "application/x-7z-compressed", "application/x-bzip2", "application/x-gzip", "application/x-rar-compressed", "application/x-tar", "application/zip":
		return "archive", true
	}

	if strings.HasSuffix(mimeType, "+json") {
		return "json", true
	}
	if strings.HasSuffix(mimeType, "+xml") {
		return "xml", true
	}
	if strings.HasPrefix(mimeType, "text/") {
		return "text", true
	}

	return "", false
}

func resourceTypeFromFetchDest(fetchDest string) (string, bool) {
	switch fetchDest {
	case "document", "frame", "iframe":
		return "html", true
	case "font":
		return "font", true
	case "image":
		return "image", true
	case "audio", "track", "video":
		return "media", true
	case "script", "serviceworker", "sharedworker", "worker":
		return "script", true
	case "style":
		return "stylesheet", true
	}

	return "", false
}

func resourceTypeFromExtension(extension string) (string, bool) {
	switch extension {
	case "htm", "html", "xhtml":
		return "html", true
	case "css":
		return "stylesheet", true
	case "cjs", "js", "mjs", "wasm":
		return "script", true
	case "json", "map":
		return "json", true
	case "xml":
		return "xml", true
	case "bmp", "gif", "ico", "jpeg", "jpg", "png", "svg", "tif", "tiff", "webp", "avif":
		return "image", true
	case "eot", "otf", "sfnt", "ttf", "woff", "woff2":
		return "font", true
	case "aac", "avi", "flac", "m3u8", "m4a", "mov", "mp3", "mp4", "oga", "ogg", "ogv", "opus", "wav", "webm":
		return "media", true
	case "7z", "br", "bz2", "gz", "rar", "tar", "tgz", "zip":
		return "archive", true
	case "csv", "md", "txt":
		return "text", true
	}

	return "", false
}

func isStaticResourceCandidate(resourceType string) bool {
	switch resourceType {
	case "archive", "font", "image", "media", "script", "stylesheet":
		return true
	default:
		return false
	}
}
